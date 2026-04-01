from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from src.database.models import Base, EmailService, RegistrationTask
from src.database.session import DatabaseSessionManager
from src.web.routes import registration as registration_routes


def _build_manager(db_name: str) -> DatabaseSessionManager:
    runtime_dir = Path("tests_runtime")
    runtime_dir.mkdir(exist_ok=True)

    db_path = runtime_dir / db_name
    if db_path.exists():
        db_path.unlink()

    manager = DatabaseSessionManager(f"sqlite:///{db_path}")
    Base.metadata.create_all(bind=manager.engine)
    return manager


def test_sync_registration_task_prefers_bound_email_service_id(monkeypatch):
    manager = _build_manager("registration_task_binding.db")

    with manager.session_scope() as session:
        first = EmailService(
            service_type="outlook",
            name="first@example.com",
            config={"email": "first@example.com", "password": "pass-1"},
            enabled=True,
            priority=0,
        )
        second = EmailService(
            service_type="outlook",
            name="second@example.com",
            config={"email": "second@example.com", "password": "pass-2"},
            enabled=True,
            priority=1,
        )
        session.add_all([first, second])
        session.flush()

        task = RegistrationTask(
            task_uuid="task-bound-service",
            status="pending",
            email_service_id=second.id,
        )
        session.add(task)

    @contextmanager
    def fake_get_db():
        session = manager.SessionLocal()
        try:
            yield session
        finally:
            session.close()

    captured = {}

    def fake_create(service_type, config):
        captured["service_type"] = service_type.value if hasattr(service_type, "value") else str(service_type)
        captured["email"] = config.get("email")
        return SimpleNamespace(service_type=service_type, config=config)

    class FakeEngine:
        def __init__(self, email_service, proxy_url=None, callback_logger=None, task_uuid=None):
            self.email_service = email_service

        def run(self):
            return SimpleNamespace(
                success=False,
                email="",
                error_message="stop after selection",
                to_dict=lambda: {},
            )

    monkeypatch.setattr(registration_routes, "get_db", fake_get_db)
    monkeypatch.setattr(registration_routes, "get_settings", lambda: SimpleNamespace())
    monkeypatch.setattr(registration_routes, "get_proxy_for_registration", lambda db: (None, None))
    monkeypatch.setattr(registration_routes.EmailServiceFactory, "create", fake_create)
    monkeypatch.setattr(registration_routes, "RegistrationEngine", FakeEngine)
    monkeypatch.setattr(registration_routes.task_manager, "update_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        registration_routes.task_manager,
        "create_log_callback",
        lambda *args, **kwargs: (lambda message: None),
    )

    registration_routes._run_sync_registration_task(
        task_uuid="task-bound-service",
        email_service_type="outlook",
        proxy=None,
        email_service_config=None,
        email_service_id=None,
    )

    assert captured["service_type"] == "outlook"
    assert captured["email"] == "second@example.com"
