"""ask.fetch against a real HTTP server that cuts a download short: the cache takes a dataset only when it is whole."""
import asyncio
import http.server
import json
import threading

import pytest

from beat import ask, wire

BODY = b"x" * 100


class Server:
    """Serves every path; `plan` says, per request in order, how many bytes of BODY to send before cutting the
    connection (None: all of it). `chunked`: no Content-Length, so nothing but the pointer states the size."""

    def __init__(self):
        self.plan, self.requests, self.chunked, self.status = [], 0, False, 200
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_GET(self):
                outer.requests += 1
                cut = outer.plan.pop(0) if outer.plan else None
                self.close_connection = True
                self.send_response(outer.status)
                if not outer.chunked:
                    self.send_header("Content-Length", str(len(BODY)))
                self.end_headers()
                self.wfile.write(BODY if cut is None else BODY[:cut])

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server(monkeypatch, tmp_path):
    s = Server()
    monkeypatch.setattr(wire, "api_url", lambda: s.url)
    monkeypatch.setattr(ask, "cache_dir", lambda: tmp_path)
    yield s
    s.close()


def pointer(bytes=len(BODY), sealed=True):
    t = {"rows": 1, "columns": ["a"]}
    if bytes is not None:
        t["bytes"] = bytes
    return {"survey": "S1", "sealed": sealed, "written_at": "T1", "tables": {"hosts": t},
            "links": {"hosts.parquet": "/o/x/datasets/S1/hosts.parquet?sig=s"}}


def fetch(p):
    return asyncio.run(ask.fetch(p))


def cached(tmp_path):
    return (tmp_path / "S1" / "hosts.parquet").read_bytes()


def test_a_whole_download_is_cached(server, tmp_path):
    p = fetch(pointer())
    assert p["dataset"] == str(tmp_path / "S1") and cached(tmp_path) == BODY
    assert json.loads((tmp_path / "S1" / "dataset.json").read_text())["written_at"] == "T1"


def test_a_cut_download_is_tried_again(server, tmp_path):
    server.plan = [10]
    fetch(pointer())
    assert server.requests == 2 and cached(tmp_path) == BODY


def test_a_download_cut_twice_fails_and_caches_nothing(server, tmp_path):
    server.plan = [10, 10]
    with pytest.raises(RuntimeError, match=r"hosts.parquet of S1 failed: got 10 bytes, Content-Length says 100"):
        fetch(pointer())
    assert list(tmp_path.iterdir()) == []


def test_with_no_content_length_the_pointer_states_the_size(server, tmp_path):
    server.chunked, server.plan = True, [10, 10]
    with pytest.raises(RuntimeError, match=r"got 10 bytes, the pointer says 100"):
        fetch(pointer())
    assert list(tmp_path.iterdir()) == []


def test_a_pointer_without_sizes_still_has_content_length(server, tmp_path):
    server.plan = [10, 10]
    with pytest.raises(RuntimeError, match="Content-Length says 100"):
        fetch(pointer(bytes=None))
    server.plan = []
    fetch(pointer(bytes=None))
    assert cached(tmp_path) == BODY


def test_an_open_surveys_pointer_size_is_not_held_against_it(server, tmp_path):
    """Its files may be written again after the pointer: the response's own length is what counts."""
    fetch(pointer(bytes=7, sealed=False))
    assert cached(tmp_path) == BODY


def test_a_refusal_is_not_tried_again(server, tmp_path):
    server.status = 403
    with pytest.raises(RuntimeError, match="403"):
        fetch(pointer())
    assert server.requests == 1 and list(tmp_path.iterdir()) == []


def test_a_whole_sealed_dataset_is_not_downloaded_again(server, tmp_path):
    fetch(pointer())
    fetch(pointer())
    assert server.requests == 1


def test_a_cached_file_cut_short_by_an_older_client_heals(server, tmp_path):
    fetch(pointer())
    (tmp_path / "S1" / "hosts.parquet").write_bytes(BODY[:10])
    fetch(pointer())
    assert server.requests == 2 and cached(tmp_path) == BODY


def test_a_failed_repair_keeps_what_was_cached(server, tmp_path):
    fetch(pointer())
    (tmp_path / "S1" / "hosts.parquet").write_bytes(BODY[:10])
    server.plan = [10, 10]
    with pytest.raises(RuntimeError):
        fetch(pointer())
    assert cached(tmp_path) == BODY[:10] and not (tmp_path / "S1.tmp").exists()
