from pathlib import Path
from contextlib import contextmanager
from types import SimpleNamespace

from src.database import crud
from src.core import register as register_module
from src.core.register import RegistrationEngine, RegistrationResult
from src.database.models import Account, Base
from src.database.session import DatabaseSessionManager


def _build_session(db_name: str):
    runtime_dir = Path("tests_runtime")
    runtime_dir.mkdir(exist_ok=True)

    db_path = runtime_dir / db_name
    if db_path.exists():
        db_path.unlink()

    manager = DatabaseSessionManager(f"sqlite:///{db_path}")
    Base.metadata.create_all(bind=manager.engine)
    return manager.SessionLocal()


def test_create_account_merge_existing_email_updates_non_empty_fields():
    session = _build_session("account_crud_merge.db")
    try:
        created = crud.create_account(
            session,
            email="dup@example.com",
            password="old-pass",
            email_service="outlook",
            refresh_token="refresh-old",
            proxy_used="http://old-proxy",
            status="failed",
            extra_data={"first": True},
        )

        merged = crud.create_account(
            session,
            email="dup@example.com",
            password="new-pass",
            email_service="outlook",
            access_token="access-new",
            refresh_token=None,
            proxy_used="",
            status="active",
            extra_data={"second": True},
            if_exists="merge",
        )

        assert merged.id == created.id
        assert merged.password == "new-pass"
        assert merged.access_token == "access-new"
        assert merged.refresh_token == "refresh-old"
        assert merged.proxy_used == "http://old-proxy"
        assert merged.status == "active"
        assert merged.extra_data == {"first": True, "second": True}
    finally:
        session.close()


def test_create_account_return_existing_email_keeps_original_record():
    session = _build_session("account_crud_return.db")
    try:
        created = crud.create_account(
            session,
            email="existing@example.com",
            password="saved-pass",
            email_service="outlook",
            status="active",
        )

        returned = crud.create_account(
            session,
            email="existing@example.com",
            password="new-pass",
            email_service="outlook",
            status="failed",
            if_exists="return",
        )

        assert returned.id == created.id
        assert returned.password == "saved-pass"
        assert returned.status == "active"
    finally:
        session.close()


def test_registration_engine_save_to_database_merges_duplicate_email(monkeypatch):
    session = _build_session("registration_save_merge.db")
    manager = session.bind
    session.close()

    @contextmanager
    def fake_get_db():
        db = DatabaseSessionManager(f"{manager.url}").SessionLocal()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(
        register_module,
        "get_settings",
        lambda: SimpleNamespace(openai_client_id="client-1"),
    )
    monkeypatch.setattr(register_module, "get_db", fake_get_db)

    engine = RegistrationEngine.__new__(RegistrationEngine)
    engine.email_service = SimpleNamespace(service_type=SimpleNamespace(value="outlook"))
    engine.email_info = {"service_id": "mailbox-1"}
    engine.proxy_url = "http://proxy-2"
    engine._dump_session_cookies = lambda: "cookie-new"
    engine._log = lambda *args, **kwargs: None

    first = RegistrationResult(
        success=True,
        email="merge@example.com",
        password="old-pass",
        access_token="access-old",
        refresh_token="refresh-old",
        session_token="session-old",
        metadata={"first": True},
        source="register",
    )
    second = RegistrationResult(
        success=True,
        email="merge@example.com",
        password="new-pass",
        access_token="access-new",
        refresh_token="",
        session_token="session-new",
        metadata={"second": True},
        source="login",
    )

    assert engine.save_to_database(first) is True
    assert engine.save_to_database(second) is True

    verify_session = DatabaseSessionManager(f"{manager.url}").SessionLocal()
    try:
        account = verify_session.query(Account).filter(Account.email == "merge@example.com").one()
        assert account.password == "new-pass"
        assert account.access_token == "access-new"
        assert account.refresh_token == "refresh-old"
        assert account.session_token == "session-new"
        assert account.cookies == "cookie-new"
        assert account.client_id == "client-1"
        assert account.source == "login"
        assert account.extra_data == {"first": True, "second": True}
    finally:
        verify_session.close()
