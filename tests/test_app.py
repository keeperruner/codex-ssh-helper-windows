import json
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from app import HTML, SetupServer, State


def test_local_ui_and_token_protection():
    state = State("test-token")
    server = SetupServer(("127.0.0.1", 0), state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urlopen(base + "/", timeout=3) as response:
            page = response.read().decode("utf-8")
        assert "Codex SSH 连接助手" in page
        assert 'id="confirm"' in page
        assert 'id="fileStore" type="checkbox"' in page
        assert 'id="fileStore" type="checkbox" checked' not in page

        try:
            urlopen(base + "/api/jobs/nope", timeout=3)
            assert False, "request without token should fail"
        except HTTPError as exc:
            assert exc.code == 403
    finally:
        server.shutdown()
        server.server_close()


def test_invalid_port_fails_without_touching_ssh_files():
    state = State("test-token")
    server = SetupServer(("127.0.0.1", 0), state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    payload = json.dumps({"host": "example.com", "port": "bad", "user": "deploy", "password": "secret", "alias": "test"}).encode()
    request = Request(base + "/api/setup", data=payload, method="POST", headers={"Content-Type": "application/json", "X-Setup-Token": "test-token"})
    try:
        with urlopen(request, timeout=3) as response:
            job_id = json.loads(response.read())["job"]
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            with state.lock:
                job = state.jobs[job_id]
                if job.state != "running":
                    break
            time.sleep(0.02)
        assert job.state == "error"
        assert "端口" in job.error
    finally:
        server.shutdown()
        server.server_close()
