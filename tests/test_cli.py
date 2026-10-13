from typer.testing import CliRunner

from opsgraph.cli import app

runner = CliRunner()


def test_help_lists_commands():
    out = runner.invoke(app, ["--help"]).output
    assert "collect" in out and "db" in out and "osv" in out


def test_collect_commands_exist():
    out = runner.invoke(app, ["collect", "--help"]).output
    assert "osv" in out and "postgresql-security" in out


def test_collect_refuses_without_contact(monkeypatch):
    monkeypatch.setenv("HTTP_CONTACT", "")
    from opsgraph.config import get_settings

    get_settings.cache_clear()
    try:
        res = runner.invoke(app, ["collect", "osv", "--dry-run"])
    finally:
        get_settings.cache_clear()
    assert res.exit_code == 2 and "HTTP_CONTACT" in res.output
