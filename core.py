from __future__ import annotations

import datetime as dt
import base64
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import paramiko


MANAGED_PREFIX = "codex-remote-setup"


class SetupError(RuntimeError):
    pass


@dataclass(frozen=True)
class ServerTarget:
    host: str
    port: int
    user: str
    alias: str


def parse_target(server: str, user: str, alias: str = "", port: int | None = None) -> ServerTarget:
    raw = server.strip()
    username = user.strip()
    if not raw:
        raise SetupError("请输入服务器地址。")
    if not username:
        raise SetupError("请输入服务器账号。")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", username):
        raise SetupError("服务器账号只能包含字母、数字、点、短横线和下划线，最长 64 个字符。")

    candidate = raw if "://" in raw else f"ssh://{raw}"
    parsed = urlparse(candidate)
    host = parsed.hostname
    if not host:
        raise SetupError("服务器地址格式无效。可输入 IP、域名、host:port 或 ssh://host:port。")
    if any(char.isspace() or char in "\"'\\#" for char in host):
        raise SetupError("服务器地址包含不允许的字符。")
    try:
        final_port = int(port or parsed.port or 22)
    except ValueError as exc:
        raise SetupError("SSH 端口必须是数字。") from exc
    if not 1 <= final_port <= 65535:
        raise SetupError("SSH 端口必须在 1 到 65535 之间。")

    # URL paths are not SSH host names. Ignore a trailing path so pasted values
    # such as host/user/password cannot accidentally become configuration data.
    safe_alias = alias.strip() or _default_alias(host, username)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", safe_alias):
        raise SetupError("连接名称只能包含字母、数字、点、短横线和下划线，最长 64 个字符。")
    return ServerTarget(host=host, port=final_port, user=username, alias=safe_alias)


def _default_alias(host: str, user: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "-", host).strip("-.")
    who = re.sub(r"[^A-Za-z0-9_.-]+", "-", user).strip("-.")
    return f"codex-{who}-{normalized}"[:64]


def ssh_paths(target: ServerTarget, home: Path | None = None) -> tuple[Path, Path, Path]:
    base = (home or Path.home()) / ".ssh"
    stem = re.sub(r"[^A-Za-z0-9_.-]", "-", target.alias)
    return base / f"{stem}_ed25519", base / "config", base / f"{stem}_known_hosts"


def ensure_keypair(private_key: Path, status=lambda _: None) -> bool:
    public_key = private_key.with_suffix(private_key.suffix + ".pub")
    if private_key.exists() and public_key.exists():
        status("复用现有专用 SSH 密钥。")
        secure_windows_path(private_key, directory=False)
        return False
    if private_key.exists() != public_key.exists():
        raise SetupError(f"密钥文件不完整，请先处理：{private_key}")

    private_key.parent.mkdir(parents=True, exist_ok=True)
    status("正在生成专用 Ed25519 密钥……")
    proc = subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"{MANAGED_PREFIX}:{private_key.stem}", "-f", str(private_key)],
        capture_output=True,
        text=True,
        creationflags=_no_window_flags(),
    )
    if proc.returncode:
        raise SetupError(f"生成 SSH 密钥失败：{_safe_error(proc.stderr)}")
    secure_windows_path(private_key.parent, directory=True)
    secure_windows_path(private_key, directory=False)
    secure_windows_path(public_key, directory=False)
    return True


def secure_windows_path(path: Path, directory: bool) -> None:
    if os.name != "nt" or not path.exists():
        return
    sid = _current_user_sid()
    grant = f"*{sid}:(OI)(CI)F" if directory else f"*{sid}:F"
    # Keep inherited ACLs on an existing .ssh directory. Removing inheritance
    # from the whole directory can disrupt unrelated keys managed by the user.
    commands = [] if directory else [["icacls", str(path), "/inheritance:r"]]
    commands.extend([
        ["icacls", str(path), "/grant:r", grant],
        ["icacls", str(path), "/grant:r", "*S-1-5-18:F"],
        ["icacls", str(path), "/grant:r", "*S-1-5-32-544:F"],
    ])
    for command in commands:
        proc = subprocess.run(command, capture_output=True, text=True, creationflags=_no_window_flags())
        if proc.returncode:
            raise SetupError(f"无法收紧 Windows 文件权限：{_safe_error(proc.stderr or proc.stdout)}")


def _current_user_sid() -> str:
    proc = subprocess.run(
        ["whoami", "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        text=True,
        creationflags=_no_window_flags(),
    )
    match = re.search(r"S-1-5-[0-9-]+", proc.stdout)
    if proc.returncode or not match:
        raise SetupError("无法读取当前 Windows 用户标识，不能安全设置密钥权限。")
    return match.group(0)


def read_public_key(public_key: Path) -> str:
    try:
        value = public_key.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SetupError(f"无法读取公钥：{exc}") from exc
    parts = value.split()
    if len(parts) < 2 or not parts[0].startswith("ssh-"):
        raise SetupError("生成的公钥格式无效。")
    return value


def bootstrap_server(
    target: ServerTarget,
    password: str,
    public_key: str,
    known_hosts_path: Path,
    status=lambda _: None,
    install_codex: bool = True,
    authenticate_codex: bool = True,
    use_file_auth_store: bool = False,
    open_browser=lambda _: None,
    on_connection_ready=lambda: None,
    confirm_host_key=lambda _: True,
) -> tuple[str, str, bool]:
    if not password:
        raise SetupError("首次配置需要服务器密码。密码不会保存。")
    status("正在用密码进行一次性登录……")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        transport = paramiko.Transport((target.host, target.port))
        transport.banner_timeout = 15
        transport.auth_timeout = 20
        transport.start_client(timeout=15)
        server_key = transport.get_remote_server_key()
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(server_key.asbytes()).digest()).decode("ascii").rstrip("=")
        status(f"服务器身份指纹：{fingerprint}")
        _verify_or_record_host_key(known_hosts_path, target, server_key, fingerprint, confirm_host_key)
        transport.auth_password(username=target.user, password=password)
        if not transport.is_authenticated():
            raise paramiko.AuthenticationException("authentication failed")
        client._transport = transport
        status("服务器身份已记录，正在安装公钥……")
        _install_authorized_key(client, public_key)
        # Persist the local SSH host as soon as key authentication is ready.
        # Remote installation or browser authentication must not hide a usable
        # host from Codex when a later optional step fails.
        on_connection_ready()
        status("正在检查远端 Codex……")
        version, executable = _remote_codex_info(client)
        if not executable and install_codex:
            status("远端尚未安装 Codex，正在下载安装官方版本……")
            _install_remote_codex(client, status)
            version, executable = _remote_codex_info(client)
            if not executable:
                raise SetupError("安装程序已结束，但没有找到 Codex 可执行文件。")
        authenticated = False
        if executable:
            _ensure_remote_codex_on_login_path(client, executable, status)
            authenticated = _remote_codex_authenticated(client, executable)
            if authenticated:
                status("远端 Codex 已经登录，无需再次认证。")
            elif authenticate_codex:
                status("正在启动远端 Codex 设备认证……")
                if use_file_auth_store:
                    _ensure_remote_auth_file_store(client, status)
                try:
                    authenticated = _authenticate_remote_codex(client, executable, status, open_browser)
                except SetupError as exc:
                    status(f"远端认证暂未完成：{exc}")
                if not authenticated:
                    status("连接配置已保存；可稍后重新运行认证，服务器仍会出现在 Codex 的 SSH 列表中。")
        return version, executable, authenticated
    except paramiko.AuthenticationException as exc:
        raise SetupError("账号或密码不正确，服务器拒绝登录。") from exc
    except (paramiko.SSHException, socket.timeout, TimeoutError, OSError) as exc:
        raise SetupError(f"无法建立 SSH 连接：{_safe_error(str(exc))}") from exc
    finally:
        client.close()


def _verify_or_record_host_key(
    path: Path,
    target: ServerTarget,
    key: paramiko.PKey,
    fingerprint: str,
    confirm_new,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    host_token = target.host if target.port == 22 else f"[{target.host}]:{target.port}"
    existing = paramiko.HostKeys()
    if path.exists():
        try:
            existing.load(str(path))
        except (OSError, paramiko.SSHException) as exc:
            raise SetupError(f"known_hosts 文件无法读取：{exc}") from exc
    if host_token in existing:
        keys = existing.lookup(host_token) or {}
        old = keys.get(key.get_name())
        if old and old.asbytes() != key.asbytes():
            raise SetupError("服务器身份密钥与本机记录不一致。为防止中间人攻击，已停止配置。")
        if old:
            return
    if not confirm_new(fingerprint):
        raise SetupError("用户未确认服务器身份指纹，配置已取消。")
    existing.add(host_token, key.get_name(), key)
    existing.save(str(path))
    secure_windows_path(path, directory=False)


def _install_authorized_key(client: paramiko.SSHClient, public_key: str) -> None:
    sftp = client.open_sftp()
    try:
        home = sftp.normalize(".")
        ssh_dir = f"{home.rstrip('/')}/.ssh"
        auth_path = f"{ssh_dir}/authorized_keys"
        try:
            sftp.stat(ssh_dir)
        except OSError:
            sftp.mkdir(ssh_dir, mode=0o700)
        sftp.chmod(ssh_dir, 0o700)

        existing = ""
        try:
            with sftp.open(auth_path, "r") as stream:
                existing = stream.read().decode("utf-8", errors="replace")
        except OSError:
            pass
        wanted_blob = public_key.split()[1]
        present = any(len(line.split()) >= 2 and line.split()[1] == wanted_blob for line in existing.splitlines())
        if not present:
            content = existing.rstrip("\r\n")
            if content:
                content += "\n"
            content += public_key + "\n"
            temp_path = f"{auth_path}.codex-setup-{os.getpid()}"
            with sftp.open(temp_path, "w") as stream:
                stream.write(content)
            sftp.chmod(temp_path, 0o600)
            try:
                sftp.posix_rename(temp_path, auth_path)
            except (AttributeError, OSError):
                backup_path = f"{auth_path}.codex-setup-backup-{os.getpid()}"
                try:
                    sftp.rename(auth_path, backup_path)
                except OSError:
                    backup_path = ""
                try:
                    sftp.rename(temp_path, auth_path)
                    if backup_path:
                        sftp.remove(backup_path)
                except OSError:
                    if backup_path:
                        sftp.rename(backup_path, auth_path)
                    raise
        sftp.chmod(auth_path, 0o600)
    finally:
        sftp.close()


def _remote_codex_info(client: paramiko.SSHClient) -> tuple[str, str]:
    command = (
        "sh -c 'p=$(command -v codex 2>/dev/null || true); "
        "for candidate in \"$p\" \"$HOME/.local/bin/codex\" \"$HOME/.codex/bin/codex\" "
        "\"$HOME/.npm-global/bin/codex\" /usr/local/bin/codex /usr/bin/codex; do "
        "if [ -n \"$candidate\" ] && [ -x \"$candidate\" ]; then "
        "printf \"%s\\n\" \"$candidate\"; \"$candidate\" --version 2>/dev/null || true; exit 0; fi; done; "
        "printf \"\\n\"'"
    )
    _, stdout, stderr = client.exec_command(command, timeout=20)
    lines = stdout.read().decode("utf-8", errors="replace").splitlines()
    error = stderr.read().decode("utf-8", errors="replace").strip()
    executable = lines[0].strip() if lines else ""
    version = lines[1].strip() if len(lines) > 1 else ""
    if error and not executable:
        return "", ""
    return version, executable


def _install_remote_codex(client: paramiko.SSHClient, status=lambda _: None) -> None:
    # This is the standalone installer command published in the official Codex
    # documentation. Download first so network and installer errors stay clear.
    command = (
        "sh -lc 'set -eu; "
        "tmp=$(mktemp); trap \"rm -f $tmp\" EXIT; "
        "if command -v curl >/dev/null 2>&1; then "
        "curl -fsSL https://chatgpt.com/codex/install.sh -o \"$tmp\"; "
        "elif command -v wget >/dev/null 2>&1; then "
        "wget -qO \"$tmp\" https://chatgpt.com/codex/install.sh; "
        "else echo \"服务器需要 curl 或 wget 才能自动安装 Codex\" >&2; exit 127; fi; "
        "CODEX_NON_INTERACTIVE=1 CODEX_INSTALL_DIR=\"$HOME/.local/bin\" sh \"$tmp\"'"
    )
    _, stdout, _ = client.exec_command(command, timeout=180)
    stdout.channel.set_combine_stderr(True)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    code = stdout.channel.recv_exit_status()
    for line in _clean_terminal_text(out).splitlines():
        if line.strip():
            status(line.strip())
    if code:
        raise SetupError(f"远端 Codex 安装失败：{_safe_error(_clean_terminal_text(out))}")


def _remote_codex_authenticated(client: paramiko.SSHClient, executable: str) -> bool:
    command = f"{shlex.quote(executable)} login status"
    _, stdout, stderr = client.exec_command(command, timeout=30)
    stdout.read()
    stderr.read()
    return stdout.channel.recv_exit_status() == 0


def _authenticate_remote_codex(
    client: paramiko.SSHClient,
    executable: str,
    status=lambda _: None,
    open_browser=lambda _: None,
    timeout_seconds: int = 600,
) -> bool:
    transport = client.get_transport()
    if not transport:
        raise SetupError("SSH 会话已断开，无法启动 Codex 认证。")
    channel = transport.open_session(timeout=20)
    channel.exec_command(f"exec {shlex.quote(executable)} app-server")
    deadline = time.monotonic() + timeout_seconds
    stdout_pending = ""
    stderr_pending = ""
    login_id = ""
    code_shown = False
    completed = False

    def send(message: dict) -> None:
        channel.sendall((json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8"))

    send(
        {
            "method": "initialize",
            "id": 0,
            "params": {
                "clientInfo": {
                    "name": "codex_remote_setup",
                    "title": "Codex Remote Setup",
                    "version": "0.2.0",
                }
            },
        }
    )
    send({"method": "initialized", "params": {}})
    send({"method": "account/login/start", "id": 1, "params": {"type": "chatgptDeviceCode"}})
    try:
        while True:
            if channel.recv_ready():
                stdout_pending += channel.recv(4096).decode("utf-8", errors="replace")
                while "\n" in stdout_pending:
                    line, stdout_pending = stdout_pending.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        message = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    event = _device_auth_event(message)
                    if event[0] == "code":
                        _, verification_url, user_code, login_id = event
                        if not _is_official_auth_url(verification_url):
                            raise SetupError("Codex 返回了非官方认证地址，已停止打开页面。")
                        status(f"一次性代码：{user_code}")
                        status(f"认证地址：{verification_url}")
                        status("登录页面卡住或账户点不动时，可稍后重试；下次请重新获取设备代码。已保存的 SSH 配置会保留。")
                        status("认证期间请保持程序和进度页打开，不要同时启动多个程序；本次最多等待 10 分钟。")
                        status("验证码已显示，正在打开本机浏览器；请在页面中输入该代码。")
                        code_shown = True
                        open_browser(verification_url)
                    elif event[0] == "success":
                        status("设备认证成功，正在确认远端登录状态……")
                        completed = True
                        return True
                    elif event[0] == "failure":
                        raise SetupError(event[1])
            if channel.recv_stderr_ready():
                stderr_pending += channel.recv_stderr(4096).decode("utf-8", errors="replace")
                if len(stderr_pending) > 8192:
                    stderr_pending = stderr_pending[-8192:]
            if channel.exit_status_ready() and not channel.recv_ready():
                detail = _safe_error(_clean_terminal_text(stderr_pending).strip())
                if not code_shown:
                    raise SetupError(f"Codex 未能生成设备验证码{f'：{detail}' if detail else '。'}")
                raise SetupError(f"设备认证进程提前结束{f'：{detail}' if detail else '。'}")
            if time.monotonic() > deadline:
                raise SetupError("等待 Codex 浏览器认证超时（10 分钟）。")
            time.sleep(0.05)
    finally:
        if login_id and not completed and not channel.closed:
            try:
                send({"method": "account/login/cancel", "id": 2, "params": {"loginId": login_id}})
            except (OSError, paramiko.SSHException):
                pass
        channel.close()


def _device_auth_event(message: object) -> tuple:
    if not isinstance(message, dict):
        return ("ignore",)
    if message.get("id") in (0, 1) and isinstance(message.get("error"), dict):
        error = message["error"]
        detail = str(error.get("message") or "Codex 设备认证接口返回错误。")
        return ("failure", detail)
    if message.get("id") == 1:
        result = message.get("result")
        if not isinstance(result, dict) or result.get("type") != "chatgptDeviceCode":
            return ("failure", "Codex 没有返回有效的设备验证码。")
        verification_url = str(result.get("verificationUrl") or "")
        user_code = str(result.get("userCode") or "")
        login_id = str(result.get("loginId") or "")
        if not verification_url or not user_code or not login_id:
            return ("failure", "Codex 返回的设备认证信息不完整。")
        return ("code", verification_url, user_code, login_id)
    method = message.get("method")
    params = message.get("params")
    if method == "account/login/completed" and isinstance(params, dict):
        if params.get("success") is True:
            return ("success",)
        return ("failure", str(params.get("error") or "设备认证未完成。"))
    if method == "account/updated" and isinstance(params, dict) and params.get("authMode") == "chatgpt":
        return ("success",)
    return ("ignore",)


def _emit_auth_output(
    text: str,
    status,
    open_browser,
    opened_urls: set[str],
    flush: bool,
) -> str:
    normalized = _clean_terminal_text(text).replace("\r", "\n")
    lines = normalized.split("\n")
    remainder = ""
    if not flush:
        remainder = lines.pop()
    for line in lines:
        value = line.strip()
        if not value:
            continue
        status(value)
        for match in re.findall(r"https://[^\s<>\"']+", value):
            url = match.rstrip(".,);]")
            if url not in opened_urls and _is_official_auth_url(url):
                opened_urls.add(url)
                status("已在本机浏览器打开官方认证页面，请输入上方的一次性代码。")
                open_browser(url)
    return remainder


def _is_official_auth_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    return parsed.scheme == "https" and (
        host == "chatgpt.com"
        or host.endswith(".chatgpt.com")
        or host == "openai.com"
        or host.endswith(".openai.com")
    )


def _clean_terminal_text(value: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)


def _ensure_remote_auth_file_store(client: paramiko.SSHClient, status=lambda _: None) -> None:
    sftp = client.open_sftp()
    try:
        home = sftp.normalize(".").rstrip("/")
        codex_dir = f"{home}/.codex"
        _sftp_mkdirs(sftp, codex_dir)
        sftp.chmod(codex_dir, 0o700)
        config_path = f"{codex_dir}/config.toml"
        existing = _sftp_read_text(sftp, config_path)
        updated = _set_top_level_toml_value(existing, "cli_auth_credentials_store", '"file"')
        if updated != existing:
            _sftp_atomic_write(sftp, config_path, updated, mode=0o600)
            status("已将远端 Codex 凭据存储设置为文件模式，适配无界面服务器。")
    finally:
        sftp.close()


def _set_top_level_toml_value(existing: str, key: str, value: str) -> str:
    line = f"{key} = {value}"
    pattern = re.compile(rf"(?m)^\s*{re.escape(key)}\s*=.*$")
    if pattern.search(existing):
        return pattern.sub(line, existing, count=1)
    content = existing.lstrip("\ufeff")
    if not content:
        return line + "\n"
    match = re.search(r"(?m)^\s*\[", content)
    if match:
        prefix = content[: match.start()].rstrip()
        suffix = content[match.start() :].lstrip()
        return f"{prefix}\n{line}\n\n{suffix}" if prefix else f"{line}\n\n{suffix}"
    return f"{content.rstrip()}\n{line}\n"


def _ensure_remote_codex_on_login_path(
    client: paramiko.SSHClient,
    executable: str,
    status=lambda _: None,
) -> None:
    found, _ = _remote_login_shell_codex_info(client)
    if found:
        return

    shell = _remote_login_shell(client)
    executable_dir = str(Path(executable).parent).replace("\\", "/")
    sftp = client.open_sftp()
    try:
        home = sftp.normalize(".").rstrip("/")
        profile_name = _profile_for_shell(shell, _remote_home_names(sftp, home))
        profile_path = f"{home}/{profile_name}"
        existing = _sftp_read_text(sftp, profile_path)
        if Path(shell).name == "fish":
            path_line = f"fish_add_path {shlex.quote(executable_dir)}"
        else:
            path_line = f"export PATH={shlex.quote(executable_dir)}:\"$PATH\""
        updated = _upsert_managed_path_block(existing, path_line)
        _sftp_atomic_write(sftp, profile_path, updated, mode=0o600)
        status(f"已将 Codex 安装目录写入远端登录配置：~/{profile_name}")
    finally:
        sftp.close()

    found, version = _remote_login_shell_codex_info(client)
    if not found:
        raise SetupError(f"Codex 已安装到 {executable}，但登录 shell 仍无法读取更新后的 PATH。")
    status(f"远端登录 shell 已识别 Codex：{version or found}")


def _remote_login_shell(client: paramiko.SSHClient) -> str:
    command = "sh -c 's=${SHELL:-}; if [ -z \"$s\" ] && command -v getent >/dev/null 2>&1; then s=$(getent passwd \"$(id -un)\" | cut -d: -f7); fi; printf \"%s\" \"${s:-/bin/sh}\"'"
    _, stdout, _ = client.exec_command(command, timeout=20)
    value = stdout.read().decode("utf-8", errors="replace").strip()
    return value or "/bin/sh"


def _remote_login_shell_codex_info(client: paramiko.SSHClient) -> tuple[str, str]:
    shell = _remote_login_shell(client)
    inner = (
        'p=$(command -v codex 2>/dev/null || true); printf "__CODEX_PATH__%s\\n" "$p"; '
        'if [ -n "$p" ]; then v=$("$p" --version 2>/dev/null || true); '
        'printf "__CODEX_VERSION__%s\\n" "$v"; fi'
    )
    command = f"{shlex.quote(shell)} -lc {shlex.quote(inner)}"
    _, stdout, _ = client.exec_command(command, timeout=30)
    lines = stdout.read().decode("utf-8", errors="replace").splitlines()
    executable = next((line.removeprefix("__CODEX_PATH__").strip() for line in lines if line.startswith("__CODEX_PATH__")), "")
    version = next((line.removeprefix("__CODEX_VERSION__").strip() for line in lines if line.startswith("__CODEX_VERSION__")), "")
    return executable, version


def _profile_for_shell(shell: str, existing_names: set[str]) -> str:
    name = Path(shell).name.lower()
    if name == "bash":
        for candidate in (".bash_profile", ".bash_login", ".profile"):
            if candidate in existing_names:
                return candidate
        return ".profile"
    if name == "zsh":
        return ".zprofile"
    if name == "fish":
        return ".config/fish/config.fish"
    return ".profile"


def _remote_home_names(sftp: paramiko.SFTPClient, home: str) -> set[str]:
    try:
        return set(sftp.listdir(home))
    except OSError:
        return set()


def _sftp_read_text(sftp: paramiko.SFTPClient, path: str) -> str:
    try:
        with sftp.open(path, "r") as stream:
            return stream.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _upsert_managed_path_block(existing: str, path_line: str) -> str:
    begin = "# BEGIN codex-remote-setup:path"
    end = "# END codex-remote-setup:path"
    pattern = re.compile(rf"(?ms)^\s*{re.escape(begin)}\s*$.*?^\s*{re.escape(end)}\s*$\r?\n?")
    cleaned = pattern.sub("", existing).rstrip()
    block = f"{begin}\n{path_line}\n{end}\n"
    return f"{cleaned}\n\n{block}" if cleaned else block


def _sftp_atomic_write(sftp: paramiko.SFTPClient, path: str, content: str, mode: int) -> None:
    parent = path.rsplit("/", 1)[0]
    _sftp_mkdirs(sftp, parent)
    temp_path = f"{path}.codex-setup-{os.getpid()}"
    with sftp.open(temp_path, "w") as stream:
        stream.write(content)
    sftp.chmod(temp_path, mode)
    try:
        sftp.posix_rename(temp_path, path)
    except (AttributeError, OSError):
        backup_path = f"{path}.codex-setup-backup-{os.getpid()}"
        try:
            sftp.rename(path, backup_path)
        except OSError:
            backup_path = ""
        try:
            sftp.rename(temp_path, path)
            if backup_path:
                sftp.remove(backup_path)
        except OSError:
            if backup_path:
                sftp.rename(backup_path, path)
            raise


def _sftp_mkdirs(sftp: paramiko.SFTPClient, path: str) -> None:
    current = ""
    for part in path.split("/"):
        if not part:
            current = "/"
            continue
        current = f"{current.rstrip('/')}/{part}"
        try:
            sftp.stat(current)
        except OSError:
            sftp.mkdir(current, mode=0o700)


def update_ssh_config(config_path: Path, target: ServerTarget, private_key: Path) -> Path | None:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    begin = f"# BEGIN {MANAGED_PREFIX}:{target.alias}"
    end = f"# END {MANAGED_PREFIX}:{target.alias}"
    old = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    pattern = re.compile(rf"(?ms)^\s*{re.escape(begin)}\s*$.*?^\s*{re.escape(end)}\s*$\r?\n?")
    cleaned = pattern.sub("", old).rstrip()
    key_value = private_key.as_posix()
    known_hosts_value = private_key.with_name(f"{target.alias}_known_hosts").as_posix()
    block = (
        f"{begin}\n"
        f"Host {target.alias}\n"
        f"    HostName {target.host}\n"
        f"    User {target.user}\n"
        f"    Port {target.port}\n"
        f"    UserKnownHostsFile \"{known_hosts_value}\"\n"
        # Keep IdentityFile after other *File directives. Some desktop UI
        # importers display the last file-valued SSH option as the identity.
        f"    IdentityFile \"{key_value}\"\n"
        "    IdentitiesOnly yes\n"
        "    StrictHostKeyChecking yes\n"
        "    ServerAliveInterval 30\n"
        f"{end}\n"
    )
    new_value = f"{cleaned}\n\n{block}" if cleaned else block

    backup = None
    if config_path.exists() and old != new_value:
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = config_path.with_name(f"config.backup-{stamp}")
        shutil.copy2(config_path, backup)
    _atomic_write(config_path, new_value)
    secure_windows_path(config_path, directory=False)
    return backup


def verify_openssh(target: ServerTarget) -> str:
    remote_command = (
        "exec \"${SHELL:-/bin/sh}\" -lc '"
        "p=$(command -v codex 2>/dev/null) || exit 127; "
        "printf \"CODEX_SSH_OK\\n%s\\n\" \"$p\"; \"$p\" --version'"
    )
    command = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=15",
        target.alias,
        remote_command,
    ]
    proc = subprocess.run(command, capture_output=True, text=True, timeout=30, creationflags=_no_window_flags())
    if proc.returncode:
        raise SetupError(f"公钥已安装，但 Windows OpenSSH 验证失败：{_safe_error(proc.stderr)}")
    if "CODEX_SSH_OK" not in proc.stdout:
        raise SetupError("SSH 验证结果异常。")
    return proc.stdout.strip()


def verify_local_environment() -> None:
    if os.name != "nt":
        raise SetupError("此版本仅支持 Windows 10/11。")
    missing = [name for name in ("ssh", "ssh-keygen") if not shutil.which(name)]
    if missing:
        raise SetupError(
            "缺少 Windows OpenSSH 客户端组件："
            + "、".join(missing)
            + "。请先在 Windows 可选功能中安装 OpenSSH 客户端。"
        )


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def _safe_error(value: str) -> str:
    compact = " ".join((value or "未知错误").split())
    return compact[:500]


def _no_window_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)
