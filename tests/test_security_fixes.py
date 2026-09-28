import pytest


@pytest.fixture
def auth_db_module(tmp_path, monkeypatch):
    import core.auth_db as module
    monkeypatch.setattr(module, "DB_PATH", str(tmp_path / "test.db"))
    return module


def test_password_change_requires_current_password(auth_db_module):
    database = auth_db_module.AuthDatabase()
    user_id = database.register_user("Test User", "test@example.com", "correct-password")
    assert user_id
    assert not database.change_password("test@example.com", "wrong-password", "new-password-123")
    assert database.change_password("test@example.com", "correct-password", "new-password-123")
    user = database.get_user_by_email("test@example.com")
    assert auth_db_module.verify_password("new-password-123", user["pwd_hash"], user["pwd_salt"])


def test_otp_is_single_use_and_invalidatable(auth_db_module):
    database = auth_db_module.AuthDatabase()
    database.store_otp("test@example.com", "ABC123")
    assert database.verify_otp("test@example.com", "ABC123")
    assert not database.verify_otp("test@example.com", "ABC123")
    database.store_otp("test@example.com", "XYZ789")
    database.invalidate_otps("test@example.com")
    assert not database.verify_otp("test@example.com", "XYZ789")


def test_session_has_expiry(auth_db_module):
    database = auth_db_module.AuthDatabase()
    user_id = database.register_user("Test User", "session@example.com", "correct-password")
    database.mark_email_verified("session@example.com")
    database.create_session(user_id)
    session = database.get_current_user_session()
    assert session["email"] == "session@example.com"
    assert session["session_expires_at"]


def test_password_change_revokes_only_target_user_sessions(auth_db_module):
    database = auth_db_module.AuthDatabase()
    first_id = database.register_user("First User", "first@example.com", "correct-password")
    second_id = database.register_user("Second User", "second@example.com", "correct-password")
    database.mark_email_verified("first@example.com")
    database.mark_email_verified("second@example.com")

    database.create_session(first_id)
    database.create_session(second_id)
    assert database.get_current_user_session()["email"] == "second@example.com"

    assert database.change_password("first@example.com", "correct-password", "new-password-123")
    assert database.get_current_user_session()["email"] == "second@example.com"

    database.create_session(first_id)
    assert database.get_current_user_session()["email"] == "first@example.com"
    assert database.change_password("first@example.com", "new-password-123", "another-password-123")
    assert database.get_current_user_session()["email"] == "second@example.com"


def test_only_first_account_is_administrator(auth_db_module):
    database = auth_db_module.AuthDatabase()
    first = database.register_user("First User", "first@example.com", "correct-password")
    second = database.register_user("Second User", "second@example.com", "correct-password")
    assert database.get_user_by_email("first@example.com")["role"] == "Administrator"
    assert database.get_user_by_email("second@example.com")["role"] == "Viewer"


def test_terminal_command_allowlist(monkeypatch):
    import ui.terminal_tab as terminal
    assert terminal.TerminalTab._is_allowed_command("ping 127.0.0.1")
    assert terminal.TerminalTab._is_allowed_command("ping -c 1 127.0.0.1")
    assert terminal.TerminalTab._is_allowed_command("arp -a")
    assert not terminal.TerminalTab._is_allowed_command("ping -f 127.0.0.1")
    assert not terminal.TerminalTab._is_allowed_command("ping -c 100000 127.0.0.1")
    assert not terminal.TerminalTab._is_allowed_command("python -c 'print(1)'")
    assert not terminal.TerminalTab._is_allowed_command("ping 127.0.0.1 && whoami")


def test_port_parser_rejects_invalid_and_oversized_ranges():
    from core.port_scanner import parse_ports_input
    assert parse_ports_input("Custom Range (Specify below)", "0,65536") == []
    assert parse_ports_input("Custom Range (Specify below)", "1-70000") == []
    assert parse_ports_input("Custom Range (Specify below)", "80,443") == [80, 443]
