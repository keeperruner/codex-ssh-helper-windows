from __future__ import annotations

import argparse
import ctypes
import json
import os
import secrets
import subprocess
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from core import (
    SetupError,
    bootstrap_server,
    ensure_keypair,
    parse_target,
    read_public_key,
    ssh_paths,
    update_ssh_config,
    verify_local_environment,
    verify_openssh,
)

APP_VERSION = "0.2.0"
_INSTANCE_MUTEX = None


HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Codex SSH 连接助手</title><style>
:root{color-scheme:light;--ink:#17202a;--muted:#61707d;--line:#dfe6eb;--brand:#0f766e;--brand2:#115e59;--ok:#166534;--bad:#b42318}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(145deg,#e9f4f1,#f7f8fa 48%,#eaf0f7);font-family:"Microsoft YaHei UI","Segoe UI",sans-serif;color:var(--ink);min-height:100vh;padding:36px 16px}
.shell{max-width:760px;margin:auto}.head{margin:0 0 18px}.head h1{font-size:28px;margin:0 0 8px;letter-spacing:-.5px}.head p{color:var(--muted);margin:0;line-height:1.6}.card{background:rgba(255,255,255,.96);border:1px solid rgba(255,255,255,.7);border-radius:18px;box-shadow:0 18px 50px rgba(22,44,64,.12);padding:26px}
.grid{display:grid;grid-template-columns:1fr 150px;gap:15px}.full{grid-column:1/-1}label{display:block;font-size:14px;font-weight:650;margin:0 0 7px}.hint{display:block;color:var(--muted);font-size:12px;margin-top:6px;line-height:1.5}input{width:100%;height:43px;border:1px solid var(--line);border-radius:9px;padding:0 12px;font:inherit;outline:none;background:#fbfcfd}input:focus{border-color:var(--brand);box-shadow:0 0 0 3px rgba(15,118,110,.12)}
.password{position:relative}.password button{position:absolute;right:6px;top:5px;border:0;background:transparent;color:var(--brand);height:33px;padding:0 9px;cursor:pointer}.primary{margin-top:21px;width:100%;height:48px;border:0;border-radius:10px;background:var(--brand);color:white;font:700 16px inherit;cursor:pointer;box-shadow:0 8px 18px rgba(15,118,110,.2)}.primary:hover{background:var(--brand2)}.primary:disabled{opacity:.58;cursor:wait}
.progress{display:none;margin-top:15px;height:4px;background:#dbe7e5;border-radius:5px;overflow:hidden}.progress:after{content:"";display:block;width:35%;height:100%;background:var(--brand);animation:run 1.2s infinite ease-in-out}@keyframes run{from{transform:translateX(-100%)}to{transform:translateX(390%)}}.status{display:none;margin-top:18px;border:1px solid var(--line);border-radius:11px;background:#f8fafb;padding:14px}.status h2{font-size:14px;margin:0 0 8px}.log{white-space:pre-wrap;color:#40505c;font:13px/1.75 "Microsoft YaHei UI",sans-serif;max-height:210px;overflow:auto}.result{font-weight:700;margin-top:8px}.ok{color:var(--ok)}.bad{color:var(--bad)}
.options{display:flex;flex-wrap:wrap;gap:12px 22px;padding:13px 14px;background:#f3f8f7;border-radius:9px}.option{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:600}.option input{width:17px;height:17px}.actions{display:none;gap:9px;margin-top:13px}.actions button{border:1px solid var(--line);background:white;border-radius:8px;height:38px;padding:0 14px;cursor:pointer;color:var(--ink)}.foot{color:var(--muted);font-size:12px;line-height:1.6;margin:17px 2px 0}.secure{display:inline-flex;align-items:center;gap:6px;color:var(--ok);font-weight:650}@media(max-width:620px){body{padding:18px 10px}.card{padding:19px}.grid{grid-template-columns:1fr}.full{grid-column:1}.head h1{font-size:24px}}
.auth-help{margin-top:18px;border:2px solid #b42318;border-radius:10px;padding:14px;background:#fff5f4;font-size:13px;line-height:1.8}.auth-help h2{margin:0 0 6px;color:#b42318;font-size:15px}.auth-help p{margin:6px 0}.auth-help strong{color:#b42318}
.confirm{display:none;margin-top:14px;border:2px solid #b45309;border-radius:10px;background:#fffbeb;padding:14px}.confirm h3{margin:0 0 7px;font-size:15px}.fingerprint{font-family:Consolas,monospace;overflow-wrap:anywhere;background:white;padding:8px;border-radius:6px}.confirm-actions{display:flex;gap:8px;margin-top:10px}.confirm-actions button{height:38px;border-radius:8px;padding:0 14px;cursor:pointer}.approve{border:0;background:#0f766e;color:white}.reject{border:1px solid #d1d5db;background:white}
</style></head><body><main class="shell"><header class="head"><h1>Codex SSH 连接助手</h1><p>Windows 社区工具：配置专用 SSH 密钥、安装远端 Codex，并引导完成认证。</p></header><section class="card"><form id="form" autocomplete="off"><div class="grid">
<div><label for="host">服务器地址</label><input id="host" required placeholder="IP、域名或 ssh://host:port"><span class="hint">例如 203.0.113.10 或 server.example.com</span></div><div><label for="port">SSH 端口</label><input id="port" required inputmode="numeric" value="22"><span class="hint">默认 22</span></div>
<div class="full"><label for="user">服务器账号</label><input id="user" required value="root"><span class="hint">日常使用建议采用最小权限账号。</span></div><div class="full"><label for="password">首次登录密码</label><div class="password"><input id="password" required type="password" autocomplete="new-password"><button type="button" id="show">显示</button></div><span class="hint"><span class="secure">● 仅用于本次连接</span>，程序不会主动把密码写入日志、SSH 配置或文件。</span></div>
<div class="full"><label for="alias">连接名称（可选）</label><input id="alias" placeholder="留空则自动生成"><span class="hint">配置完成后，该名称会出现在 Codex 的 SSH 连接列表中。</span></div><div class="full options"><label class="option"><input id="install" type="checkbox" checked>远端缺少 Codex 时自动安装</label><label class="option"><input id="authenticate" type="checkbox" checked>自动拉起本机浏览器完成远端认证</label><label class="option"><input id="fileStore" type="checkbox">无界面兼容：把远端登录令牌存入受限文件</label><span class="hint">仅当浏览器提示成功、远端却仍显示未登录时启用。文件位于远端 ~/.codex/auth.json，应按密码保护。</span></div></div><button class="primary" id="submit" type="submit">一键安装、认证并连接</button><div class="progress" id="progress"></div></form>
<section class="status" id="status"><h2>执行进度</h2><div class="log" id="log"></div><div class="confirm" id="confirm"><h3>确认服务器身份指纹</h3><p>请通过服务器服务商控制台核对下面的 SHA-256 指纹。只有完全一致时才继续。</p><div class="fingerprint" id="fingerprint"></div><div class="confirm-actions"><button class="approve" id="approve" type="button">指纹一致，继续</button><button class="reject" id="reject" type="button">不一致，取消</button></div></div><div class="result" id="result"></div><div class="actions" id="actions"><button id="copy" type="button">复制连接名称</button><button id="terminal" type="button">打开 SSH 终端</button></div></section><p class="foot">设备认证时，程序会打开 OpenAI 官方页面。完成后到 Codex → 设置 → 连接 → SSH，启用连接并选择远端项目文件夹。本项目是社区工具，并非 OpenAI 官方产品。</p></section></main>
<aside class="auth-help shell" aria-label="登录页面卡顿处理"><h2>登录页面卡住、账户点不动？可以稍后再认证</h2><p>其他网站正常，不代表 OpenAI 登录请求一定正常。页面卡顿本身不能确定是风控，也不代表 SSH 配置失败。</p><p><strong>晚点重试：</strong>关闭旧认证页面，退出旧的一键连接程序；下次只启动一个程序，使用相同服务器和连接名称重新操作。<strong>重新获取设备代码，不要沿用旧代码。</strong>已保存的 SSH 配置和密钥会保留。</p><p><strong>正在认证时：</strong>保持连接程序及进度页打开，不要连续重试或同时启动多个程序。浏览器提示成功后，回到进度页确认远端认证结果；本程序最多等待 10 分钟。</p><p><strong>页面仍卡顿：</strong>可尝试无痕窗口、其他浏览器，或在手机浏览器打开程序显示的官方认证地址，输入本次设备代码。仍不成功就稍后再试；单凭页面无响应无法判断具体原因。</p></aside>
<script>
const startup=new URLSearchParams(location.hash.slice(1)),token=startup.get('token')||sessionStorage.getItem('setupToken')||'';if(token)sessionStorage.setItem('setupToken',token);history.replaceState(null,'',location.pathname);let job='',timer=null,lastAlias='',pollFailures=0,confirming=false;const $=id=>document.getElementById(id),log=$('log'),result=$('result'),statusBox=$('status'),actions=$('actions');
$('show').onclick=()=>{const p=$('password'),show=p.type==='password';p.type=show?'text':'password';$('show').textContent=show?'隐藏':'显示'};
$('form').onsubmit=async e=>{e.preventDefault();$('submit').disabled=true;$('progress').style.display='block';statusBox.style.display='block';actions.style.display='none';result.textContent='';result.className='result';log.textContent='正在开始安全配置……';pollFailures=0;try{const r=await fetch('/api/setup',{method:'POST',headers:{'Content-Type':'application/json','X-Setup-Token':token},body:JSON.stringify({host:$('host').value,port:$('port').value,user:$('user').value,password:$('password').value,alias:$('alias').value,install_codex:$('install').checked,authenticate_codex:$('authenticate').checked,use_file_auth_store:$('fileStore').checked})});const d=await r.json();$('password').value='';if(!r.ok)throw new Error(d.error||'无法启动配置');job=d.job;timer=setInterval(poll,650);poll()}catch(err){finish(false,err.message)}};
async function poll(){try{const r=await fetch('/api/jobs/'+encodeURIComponent(job),{headers:{'X-Setup-Token':token}}),d=await r.json();if(!r.ok)throw new Error(d.error||'无法读取进度');pollFailures=0;result.textContent='';result.className='result';log.textContent=(d.logs||[]).join('\n');log.scrollTop=log.scrollHeight;if(d.state==='confirm_host_key'){confirming=true;$('fingerprint').textContent=d.fingerprint;$('confirm').style.display='block'}else if(d.state==='done'){lastAlias=d.alias;finish(true,d.codex_ready&&d.authenticated?'连接已配置成功，远端 Codex 已安装并完成认证。':d.codex_ready?'连接与 Codex 已就绪，但尚未完成认证。':'SSH 已配置成功；未安装远端 Codex。')}else if(d.state==='error')finish(false,d.error)}catch(err){pollFailures++;if(pollFailures<10){result.textContent='本地界面连接暂时中断，正在自动重试……';result.className='result'}else{finish(false,'本地配置程序连接已中断。请关闭这个旧页面，再重新打开最新版程序。')}}}
async function decideHostKey(accept){if(!confirming)return;confirming=false;await fetch('/api/host-key',{method:'POST',headers:{'Content-Type':'application/json','X-Setup-Token':token},body:JSON.stringify({job,accept})});$('confirm').style.display='none'}
$('approve').onclick=()=>decideHostKey(true);$('reject').onclick=()=>decideHostKey(false);
function finish(ok,msg){if(timer)clearInterval(timer);timer=null;$('submit').disabled=false;$('progress').style.display='none';statusBox.style.display='block';result.textContent=msg;result.className='result '+(ok?'ok':'bad');if(ok)actions.style.display='flex'}
$('copy').onclick=async()=>{await navigator.clipboard.writeText(lastAlias);$('copy').textContent='已复制';setTimeout(()=>$('copy').textContent='复制连接名称',1200)};$('terminal').onclick=()=>fetch('/api/terminal',{method:'POST',headers:{'Content-Type':'application/json','X-Setup-Token':token},body:JSON.stringify({alias:lastAlias})});
</script></body></html>"""


@dataclass
class Job:
    state: str = "running"
    logs: list[str] = field(default_factory=list)
    alias: str = ""
    codex_ready: bool = False
    authenticated: bool = False
    error: str = ""
    fingerprint: str = ""
    host_key_decision: bool | None = None
    host_key_event: threading.Event = field(default_factory=threading.Event)


class State:
    def __init__(self, token: str) -> None:
        self.token = token
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()
        self.valid_aliases: set[str] = set()
        self.last_activity = time.monotonic()


class Handler(BaseHTTPRequestHandler):
    server: "SetupServer"

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        self.server.state.last_activity = time.monotonic()
        if parsed.path == "/":
            self._send(HTTPStatus.OK, HTML, "text/html; charset=utf-8")
            return
        if parsed.path.startswith("/api/jobs/"):
            if not self._authorized():
                return
            job_id = parsed.path.removeprefix("/api/jobs/")
            with self.server.state.lock:
                job = self.server.state.jobs.get(job_id)
                if not job:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "任务不存在。"})
                    return
                self._json(HTTPStatus.OK, {"state": job.state, "logs": job.logs, "alias": job.alias, "codex_ready": job.codex_ready, "authenticated": job.authenticated, "error": job.error, "fingerprint": job.fingerprint})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "页面不存在。"})

    def do_POST(self) -> None:
        self.server.state.last_activity = time.monotonic()
        if not self._authorized():
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 65536:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "请求内容无效。"})
            return
        try:
            data = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "请求内容无效。"})
            return
        if self.path == "/api/setup":
            try:
                verify_local_environment()
            except SetupError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            job_id = secrets.token_urlsafe(16)
            with self.server.state.lock:
                self.server.state.jobs[job_id] = Job()
            threading.Thread(target=self.server.run_setup, args=(job_id, data), daemon=True).start()
            self._json(HTTPStatus.ACCEPTED, {"job": job_id})
            return
        if self.path == "/api/host-key":
            job_id = str(data.get("job", ""))
            accept = data.get("accept") is True
            with self.server.state.lock:
                job = self.server.state.jobs.get(job_id)
                if not job or job.state != "confirm_host_key":
                    self._json(HTTPStatus.CONFLICT, {"error": "当前没有等待确认的服务器指纹。"})
                    return
                job.host_key_decision = accept
                job.host_key_event.set()
            self._json(HTTPStatus.OK, {"ok": True})
            return
        if self.path == "/api/terminal":
            alias = str(data.get("alias", ""))
            with self.server.state.lock:
                allowed = alias in self.server.state.valid_aliases
            if not allowed:
                self._json(HTTPStatus.FORBIDDEN, {"error": "连接名称无效。"})
                return
            subprocess.Popen(["cmd.exe", "/k", "ssh", alias], creationflags=subprocess.CREATE_NEW_CONSOLE)
            self._json(HTTPStatus.OK, {"ok": True})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "接口不存在。"})

    def _authorized(self) -> bool:
        if not secrets.compare_digest(self.headers.get("X-Setup-Token", ""), self.server.state.token):
            self._json(HTTPStatus.FORBIDDEN, {"error": "本地会话已失效，请重新打开程序。"})
            return False
        return True

    def _json(self, status: HTTPStatus, value: dict) -> None:
        self._send(status, json.dumps(value, ensure_ascii=False), "application/json; charset=utf-8")

    def _send(self, status: HTTPStatus, content: str, content_type: str) -> None:
        body = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)


class SetupServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], state: State) -> None:
        super().__init__(address, Handler)
        self.state = state

    def run_setup(self, job_id: str, data: dict) -> None:
        password = str(data.get("password", ""))
        data["password"] = ""

        def status(message: str) -> None:
            with self.state.lock:
                self.state.jobs[job_id].logs.append(message)

        try:
            try:
                port = int(str(data.get("port", "22")).strip())
            except ValueError as exc:
                raise SetupError("SSH 端口必须是数字。") from exc
            target = parse_target(str(data.get("host", "")), str(data.get("user", "")), str(data.get("alias", "")), port)
            private_key, config_path, known_hosts = ssh_paths(target)
            status(f"目标：{target.user}@{target.host}:{target.port}")
            ensure_keypair(private_key, status)
            public_key = read_public_key(private_key.with_suffix(private_key.suffix + ".pub"))
            connection_saved = False

            def save_connection() -> None:
                nonlocal connection_saved
                if connection_saved:
                    return
                status("正在写入 Windows SSH 配置……")
                backup = update_ssh_config(config_path, target, private_key)
                if backup:
                    status(f"原配置已备份：{backup.name}")
                status(f"Codex 身份文件：{private_key}")
                status("请勿选择 .pub 公钥或 *_known_hosts 服务器指纹文件。")
                connection_saved = True

            def confirm_host_key(fingerprint: str) -> bool:
                with self.state.lock:
                    job = self.state.jobs[job_id]
                    job.fingerprint = fingerprint
                    job.host_key_decision = None
                    job.host_key_event.clear()
                    job.state = "confirm_host_key"
                    job.logs.append("首次连接需要核对服务器身份指纹。请在页面确认后继续。")
                if not job.host_key_event.wait(timeout=300):
                    raise SetupError("等待服务器指纹确认超时（5 分钟）。")
                with self.state.lock:
                    decision = job.host_key_decision is True
                    job.state = "running"
                return decision

            version, executable, authenticated = bootstrap_server(
                target,
                password,
                public_key,
                known_hosts,
                status,
                install_codex=bool(data.get("install_codex", True)),
                authenticate_codex=bool(data.get("authenticate_codex", True)),
                use_file_auth_store=bool(data.get("use_file_auth_store", False)),
                open_browser=webbrowser.open,
                on_connection_ready=save_connection,
                confirm_host_key=confirm_host_key,
            )
            password = ""
            save_connection()
            status("正在用 Windows OpenSSH 做最终验证……")
            verify_openssh(target)
            status(f"远端 Codex 已就绪：{version or executable}" if executable else "SSH 已就绪，但远端登录 shell 中未找到 codex。")
            if executable and not authenticated:
                status("远端 Codex 尚未认证。")
            status("在 Codex → 设置 → 连接 → SSH 中请按下面填写：")
            status(f"显示名称：{target.alias}")
            status(f"主机名：{target.alias}（必须使用 SSH 别名，不要填写裸 IP）")
            status("SSH 端口：留空（或填写 22）")
            status(f"身份文件路径：{private_key}")
            with self.state.lock:
                job = self.state.jobs[job_id]
                job.state, job.alias, job.codex_ready, job.authenticated = "done", target.alias, bool(executable), authenticated
                self.state.valid_aliases.add(target.alias)
        except Exception as exc:
            password = ""
            message = str(exc) if isinstance(exc, SetupError) else f"发生意外错误：{exc}"
            with self.state.lock:
                job = self.state.jobs[job_id]
                job.logs.append(f"失败：{message}")
                job.error, job.state = message, "error"


def idle_shutdown(server: SetupServer, timeout_seconds: int = 1800) -> None:
    while True:
        time.sleep(30)
        with server.state.lock:
            running = any(job.state == "running" for job in server.state.jobs.values())
        if not running and time.monotonic() - server.state.last_activity > timeout_seconds:
            server.shutdown()
            return


def main() -> None:
    global _INSTANCE_MUTEX
    if os.name == "nt":
        _INSTANCE_MUTEX = ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\CodexSSHHelperCommunity")
        if ctypes.windll.kernel32.GetLastError() == 183:
            ctypes.windll.user32.MessageBoxW(None, "程序已经在运行。请使用已打开的浏览器页面。", "Codex SSH 连接助手", 0x40)
            return
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--port", type=int, default=0)
    args, _ = parser.parse_known_args()
    token = secrets.token_urlsafe(32)
    state = State(token)
    server = SetupServer(("127.0.0.1", args.port), state)
    url = f"http://127.0.0.1:{server.server_address[1]}/#token={token}"
    threading.Thread(target=idle_shutdown, args=(server,), daemon=True).start()
    if not args.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
