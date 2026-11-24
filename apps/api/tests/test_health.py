from fleet.api.main import health
from fleet.settings import get_settings


def test_health_returns_build_and_uptime(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://fleet:fleet@localhost/fleet")
    monkeypatch.setenv("APP_ENV", "test")
    get_settings.cache_clear()
    assert get_settings().app_env == "test"
    body = health()
    assert body["status"] == "ok"
    assert isinstance(body["uptime_seconds"], float)
    assert body["build_version"] == "dev"
