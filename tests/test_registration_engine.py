import base64
import json

from src.config.constants import EmailServiceType, OPENAI_API_ENDPOINTS, OPENAI_PAGE_TYPES
from src.core.http_client import OpenAIHTTPClient
from src.core.openai.oauth import OAuthStart
from src.core.register import RegistrationEngine
from src.core.anyauto.register_flow import AnyAutoRegistrationEngine
from src.services.base import BaseEmailService


class DummyResponse:
    def __init__(self, status_code=200, payload=None, text="", headers=None, on_return=None):
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.headers = headers or {}
        self.on_return = on_return

    def json(self):
        if self._payload is None:
            raise ValueError("no json payload")
        return self._payload


class QueueSession:
    def __init__(self, steps):
        self.steps = list(steps)
        self.calls = []
        self.cookies = {}

    def get(self, url, **kwargs):
        return self._request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._request("POST", url, **kwargs)

    def request(self, method, url, **kwargs):
        return self._request(method.upper(), url, **kwargs)

    def close(self):
        return None

    def _request(self, method, url, **kwargs):
        self.calls.append({
            "method": method,
            "url": url,
            "kwargs": kwargs,
        })
        if not self.steps:
            raise AssertionError(f"unexpected request: {method} {url}")
        expected_method, expected_url, response = self.steps.pop(0)
        assert method == expected_method
        assert url == expected_url
        if callable(response):
            response = response(self)
        if response.on_return:
            response.on_return(self)
        return response


class FakeEmailService(BaseEmailService):
    def __init__(self, codes):
        super().__init__(EmailServiceType.TEMPMAIL)
        self.codes = list(codes)
        self.otp_requests = []

    def create_email(self, config=None):
        return {
            "email": "tester@example.com",
            "service_id": "mailbox-1",
        }

    def get_verification_code(self, email, email_id=None, timeout=120, pattern=r"(?<!\d)(\d{6})(?!\d)", otp_sent_at=None):
        self.otp_requests.append({
            "email": email,
            "email_id": email_id,
            "otp_sent_at": otp_sent_at,
        })
        if not self.codes:
            raise AssertionError("no verification code queued")
        return self.codes.pop(0)

    def list_emails(self, **kwargs):
        return []

    def delete_email(self, email_id):
        return True

    def check_health(self):
        return True


class FakeOAuthManager:
    def __init__(self):
        self.start_calls = 0
        self.callback_calls = []

    def start_oauth(self):
        self.start_calls += 1
        return OAuthStart(
            auth_url=f"https://auth.example.test/flow/{self.start_calls}",
            state=f"state-{self.start_calls}",
            code_verifier=f"verifier-{self.start_calls}",
            redirect_uri="http://localhost:1455/auth/callback",
        )

    def handle_callback(self, callback_url, expected_state, code_verifier):
        self.callback_calls.append({
            "callback_url": callback_url,
            "expected_state": expected_state,
            "code_verifier": code_verifier,
        })
        return {
            "account_id": "acct-1",
            "access_token": "access-1",
            "refresh_token": "refresh-1",
            "id_token": "id-1",
        }


class FakeOpenAIClient:
    def __init__(self, sessions, sentinel_tokens):
        self._sessions = list(sessions)
        self._session_index = 0
        self._session = self._sessions[0]
        self._sentinel_tokens = list(sentinel_tokens)

    @property
    def session(self):
        return self._session

    def check_ip_location(self):
        return True, "US"

    def check_sentinel(self, did):
        if not self._sentinel_tokens:
            raise AssertionError("no sentinel token queued")
        return self._sentinel_tokens.pop(0)

    def close(self):
        if self._session_index + 1 < len(self._sessions):
            self._session_index += 1
            self._session = self._sessions[self._session_index]


def _workspace_cookie(workspace_id):
    payload = base64.urlsafe_b64encode(
        json.dumps({"workspaces": [{"id": workspace_id}]}).encode("utf-8")
    ).decode("ascii").rstrip("=")
    return f"{payload}.sig"


def _response_with_did(did):
    return DummyResponse(
        status_code=200,
        text="ok",
        on_return=lambda session: session.cookies.__setitem__("oai-did", did),
    )


def _response_with_login_cookies(workspace_id="ws-1", session_token="session-1"):
    def setter(session):
        session.cookies["oai-client-auth-session"] = _workspace_cookie(workspace_id)
        session.cookies["__Secure-next-auth.session-token"] = session_token

    return DummyResponse(status_code=200, payload={}, on_return=setter)


def test_check_sentinel_sends_non_empty_pow(monkeypatch):
    session = QueueSession([
        ("POST", OPENAI_API_ENDPOINTS["sentinel"], DummyResponse(payload={"token": "sentinel-token"})),
    ])
    client = OpenAIHTTPClient()
    client._session = session

    monkeypatch.setattr(
        "src.core.http_client.build_sentinel_pow_token",
        lambda user_agent: "gAAAAACpow-token",
    )

    token = client.check_sentinel("device-1")

    assert token == "sentinel-token"
    body = json.loads(session.calls[0]["kwargs"]["data"])
    assert body["id"] == "device-1"
    assert body["flow"] == "authorize_continue"
    assert body["p"] == "gAAAAACpow-token"


def test_run_maps_anyauto_success_result(monkeypatch):
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)

    def fake_run(self):
        self.email_info = {"email": "tester@example.com", "service_id": "mailbox-1"}
        self.email = "tester@example.com"
        self.inbox_email = "tester@example.com"
        self.password = "Passw0rd!"
        self.session = object()
        self.device_id = "did-v2"
        return {
            "success": True,
            "access_token": "access-v2",
            "refresh_token": "refresh-v2",
            "id_token": "id-v2",
            "session_token": "session-v2",
            "account_id": "acct-v2",
            "workspace_id": "ws-v2",
            "metadata": {"auth_provider": "next-auth"},
        }

    monkeypatch.setattr(AnyAutoRegistrationEngine, "run", fake_run)

    result = engine.run()

    assert result.success is True
    assert result.source == "register"
    assert result.email == "tester@example.com"
    assert result.password == "Passw0rd!"
    assert result.device_id == "did-v2"
    assert result.account_id == "acct-v2"
    assert result.workspace_id == "ws-v2"
    assert result.session_token == "session-v2"
    assert result.access_token == "access-v2"
    assert result.refresh_token == "refresh-v2"
    assert result.id_token == "id-v2"
    assert result.metadata["auth_provider"] == "next-auth"
    assert result.metadata["registration_flow"] == "any-auto-register"
    assert result.metadata["has_session_token"] is True
    assert result.metadata["has_access_token"] is True


def test_run_maps_anyauto_phone_required_result(monkeypatch):
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)

    def fake_run(self):
        self.email_info = {"email": "tester@example.com", "service_id": "mailbox-1"}
        self.email = "tester@example.com"
        self.inbox_email = "tester@example.com"
        self.password = "Passw0rd!"
        self.device_id = "did-v2"
        return {
            "success": True,
            "metadata": {
                "phone_verification_required": True,
                "token_pending": True,
                "oauth_error": "add_phone required",
            },
        }

    monkeypatch.setattr(AnyAutoRegistrationEngine, "run", fake_run)

    result = engine.run()

    assert result.success is True
    assert result.source == "register"
    assert result.email == "tester@example.com"
    assert result.password == "Passw0rd!"
    assert result.device_id == "did-v2"
    assert result.access_token == ""
    assert result.session_token == ""
    assert result.metadata["phone_verification_required"] is True
    assert result.metadata["token_pending"] is True
    assert result.metadata["oauth_error"] == "add_phone required"
    assert result.metadata["registration_flow"] == "any-auto-register"
    assert result.metadata["has_session_token"] is False
    assert result.metadata["has_access_token"] is False
