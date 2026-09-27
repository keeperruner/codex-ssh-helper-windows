import inspect
from pathlib import Path

import pytest

from core import (
    SetupError,
    _device_auth_event,
    _emit_auth_output,
    _is_official_auth_url,
    _profile_for_shell,
    _set_top_level_toml_value,
    _upsert_managed_path_block,
    parse_target,
    ssh_paths,
    update_ssh_config,
    bootstrap_server,
)


def test_parse_plain_host():
    target = parse_target("192.0.2.10", "root")
    assert target.host == "192.0.2.10"
    assert target.port == 22
    assert target.alias == "codex-root-192.0.2.10"


def test_parse_url_and_explicit_port():
    target = parse_target("ssh://example.com:2202/path", "deploy", "prod")
    assert (target.host, target.port, target.user, target.alias) == ("example.com", 2202, "deploy", "prod")


def test_pasted_path_is_not_treated_as_credentials():
    target = parse_target("192.0.2.10/root/not-a-password-field", "root")
    assert target.host == "192.0.2.10"
    assert target.user == "root"


def test_reject_bad_alias():
    with pytest.raises(SetupError):
        parse_target("example.com", "deploy", "bad alias")


def test_reject_config_injection_in_user_and_host():
    with pytest.raises(SetupError):
        parse_target("example.com", "root\nProxyCommand evil")
    with pytest.raises(SetupError):
        parse_target("bad host.example", "root")


def test_config_preserves_user_content_and_is_idempotent(tmp_path: Path):
    target = parse_target("example.com", "deploy", "prod")
    _, config, _ = ssh_paths(target, tmp_path)
    config.parent.mkdir(parents=True)
    config.write_text("Host personal\n    HostName old.example\n", encoding="utf-8")
    key = config.parent / "prod_ed25519"
    update_ssh_config(config, target, key)
    first = config.read_text(encoding="utf-8")
    update_ssh_config(config, target, key)
    second = config.read_text(encoding="utf-8")
    assert first == second
    assert "Host personal" in second
    assert second.count("Host prod") == 1
    assert 'IdentityFile "' in second
    assert 'UserKnownHostsFile "' in second
    assert second.index('UserKnownHostsFile "') < second.index('IdentityFile "')


def test_existing_managed_block_is_replaced(tmp_path: Path):
    target = parse_target("new.example", "deploy", "prod")
    _, config, _ = ssh_paths(target, tmp_path)
    config.parent.mkdir(parents=True)
    config.write_text(
        "# BEGIN codex-remote-setup:prod\nHost prod\n    HostName old.example\n# END codex-remote-setup:prod\n",
        encoding="utf-8",
    )
    update_ssh_config(config, target, config.parent / "key")
    result = config.read_text(encoding="utf-8")
    assert "old.example" not in result
    assert "new.example" in result
    assert result.count("# BEGIN codex-remote-setup:prod") == 1


def test_only_official_auth_urls_are_allowed():
    assert _is_official_auth_url("https://auth.openai.com/device")
    assert _is_official_auth_url("https://chatgpt.com/codex/device")
    assert not _is_official_auth_url("https://openai.com.example.org/device")
    assert not _is_official_auth_url("http://auth.openai.com/device")


def test_auth_output_opens_official_url_and_strips_ansi():
    logs = []
    opened = []
    seen = set()
    remainder = _emit_auth_output(
        "\x1b[32mCode: ABCD-EFGH\x1b[0m\nhttps://auth.openai.com/device\nhttps://evil.example/device\n",
        logs.append,
        opened.append,
        seen,
        flush=True,
    )
    assert remainder == ""
    assert opened == ["https://auth.openai.com/device"]
    assert any("ABCD-EFGH" in line for line in logs)


def test_structured_device_auth_code_is_extracted():
    event = _device_auth_event(
        {
            "id": 1,
            "result": {
                "type": "chatgptDeviceCode",
                "loginId": "login-1",
                "verificationUrl": "https://auth.openai.com/codex/device",
                "userCode": "ABCD-1234",
            },
        }
    )
    assert event == ("code", "https://auth.openai.com/codex/device", "ABCD-1234", "login-1")


def test_structured_device_auth_completion_and_error():
    assert _device_auth_event(
        {"method": "account/login/completed", "params": {"success": True, "error": None}}
    ) == ("success",)
    assert _device_auth_event(
        {"method": "account/login/completed", "params": {"success": False, "error": "denied"}}
    ) == ("failure", "denied")
    assert _device_auth_event({"id": 1, "error": {"message": "unsupported"}}) == (
        "failure",
        "unsupported",
    )


def test_login_profile_selection_matches_shell_rules():
    assert _profile_for_shell("/bin/bash", {".bash_profile", ".profile"}) == ".bash_profile"
    assert _profile_for_shell("/bin/bash", {".profile"}) == ".profile"
    assert _profile_for_shell("/usr/bin/zsh", set()) == ".zprofile"
    assert _profile_for_shell("/usr/bin/fish", set()) == ".config/fish/config.fish"


def test_managed_path_block_is_idempotent_and_preserves_profile():
    original = "export EDITOR=vim\n"
    once = _upsert_managed_path_block(original, 'export PATH="$HOME/.local/bin:$PATH"')
    twice = _upsert_managed_path_block(once, 'export PATH="$HOME/.local/bin:$PATH"')
    assert once == twice
    assert "export EDITOR=vim" in twice
    assert twice.count("# BEGIN codex-remote-setup:path") == 1


def test_auth_store_setting_is_top_level_and_idempotent():
    original = '[model_providers.local]\nname = "Local"\n'
    once = _set_top_level_toml_value(original, "cli_auth_credentials_store", '"file"')
    twice = _set_top_level_toml_value(once, "cli_auth_credentials_store", '"file"')
    assert once == twice
    assert once.startswith('cli_auth_credentials_store = "file"\n')
    assert once.index("cli_auth_credentials_store") < once.index("[model_providers.local]")


def test_auth_store_existing_value_is_replaced():
    result = _set_top_level_toml_value(
        'cli_auth_credentials_store = "keyring"\nmodel = "test"\n',
        "cli_auth_credentials_store",
        '"file"',
    )
    assert 'cli_auth_credentials_store = "file"' in result
    assert "keyring" not in result


def test_file_credential_store_is_opt_in():
    parameter = inspect.signature(bootstrap_server).parameters["use_file_auth_store"]
    assert parameter.default is False
