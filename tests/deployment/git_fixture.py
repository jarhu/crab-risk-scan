"""Smart HTTP fixture and real Git client on a disposable internal Docker network."""
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit

HOST = "crab-git.test"
PORT = 8081
MARKER = "offline deployment fixture\n"


class GitHTTP(BaseHTTPRequestHandler):
    def serve(self):
        path = urlsplit(self.path)
        if path.path == "/ready":
            self.send_response(200)
            self.end_headers()
            return
        if path.path not in {"/fixture.git/info/refs", "/fixture.git/git-upload-pack"}:
            self.send_error(404)
            return
        size = int(self.headers.get("Content-Length", 0))
        if not 0 <= size <= 1024 * 1024:
            self.send_error(413)
            return
        env = dict(os.environ, GIT_PROJECT_ROOT=self.server.root, GIT_HTTP_EXPORT_ALL="1",
                   PATH_INFO=path.path, QUERY_STRING=path.query, REQUEST_METHOD=self.command,
                   CONTENT_TYPE=self.headers.get("Content-Type", ""), CONTENT_LENGTH=str(size))
        output = subprocess.run(["git", "http-backend"], env=env, input=self.rfile.read(size),
                                stdout=subprocess.PIPE, check=True, timeout=30).stdout
        headers, data = output.split(b"\r\n\r\n", 1)
        fields = dict(line.decode().split(": ", 1) for line in headers.split(b"\r\n"))
        self.send_response(int(fields.pop("Status", "200").split()[0]))
        for key, value in fields.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = serve


def serve(root):
    repo = root / "seed"
    subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(repo)], check=True)
    (repo / "marker.txt").write_text(MARKER)
    subprocess.run(["git", "-C", str(repo), "add", "marker.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                    "commit", "--quiet", "-m", "fixture"], check=True)
    subprocess.run(["git", "clone", "--quiet", "--bare", str(repo), str(root / "fixture.git")], check=True)
    with ThreadingHTTPServer(("", PORT), GitHTTP) as server:
        server.root = str(root)
        server.serve_forever()


def checkout(root):
    from crab_risk_scan import worker

    url = f"http://{HOST}:{PORT}"
    for attempt in range(30):
        try:
            with urllib.request.urlopen(url + "/ready", timeout=2):
                break
        except urllib.error.URLError:
            if attempt == 29:
                raise
            time.sleep(1)
    expected = socket.gethostbyname(HOST)
    client = worker.Worker(None, "smoke", allow_git=True, git_hosts=[(HOST, PORT)])
    destination = root / "checkout"
    trace = root / "git-curl.log"
    git_environment = worker.git_environment

    # Only enable libcurl's diagnostic output. DNS validation, Git, curl and the HTTP server are real.
    def traced_environment(home):
        return dict(git_environment(home), GIT_TRACE_CURL=str(trace), GIT_TRACE_CURL_NO_DATA="1")

    with patch.object(worker, "git_environment", traced_environment):
        revision = client.checkout(url + "/fixture.git", "main", destination,
                                   SimpleNamespace(cancelled=threading.Event()))
    assert revision and (destination / "marker.txt").read_text() == MARKER
    assert f"Added {HOST}:{PORT}:{expected} to DNS cache" in trace.read_text(), "Git did not use the validated pin"
    print(f"Git checked out {revision} through the validated address for {HOST}", flush=True)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        {"serve": serve, "checkout": checkout}[sys.argv[1]](Path(tmp))
