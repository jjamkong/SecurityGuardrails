"""SecurityGuardrails 로컬 데모.

본인 PC(127.0.0.1)에 임시 '취약한' 웹루트를 잠깐 띄우고 그 대상을 점검한다.
→ 외부 사이트를 건드리지 않으므로 승인/합법성 문제 없이 도구 동작을 확인할 수 있다.

실행:
    python examples/run_demo.py
"""

from __future__ import annotations

import functools
import http.server
import os
import socketserver
import tempfile
import threading

from sg.scanner import run_scan
from sg.scope import build_scope


def _make_vulnerable_webroot() -> str:
    """의도적으로 헐겁게 구성한 임시 웹루트(노출된 .git/.env 포함)를 만든다."""
    root = tempfile.mkdtemp(prefix="sg-demo-")
    with open(os.path.join(root, "index.html"), "w", encoding="utf-8") as fh:
        fh.write("<!doctype html><html><body><h1>demo</h1></body></html>")
    os.makedirs(os.path.join(root, ".git"), exist_ok=True)
    with open(os.path.join(root, ".git", "HEAD"), "w", encoding="utf-8") as fh:
        fh.write("ref: refs/heads/main\n")
    with open(os.path.join(root, ".env"), "w", encoding="utf-8") as fh:
        fh.write("DB_PASSWORD=demo-only\nAPI_KEY=demo-123\n")
    return root


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # 접근 로그 숨김
        pass


def main() -> None:
    webroot = _make_vulnerable_webroot()
    handler = functools.partial(_QuietHandler, directory=webroot)
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    try:
        target = f"http://127.0.0.1:{port}/"
        print(f"[*] 점검 대상(로컬 본인 PC, 임시): {target}")

        # 승인/스코프 — 본인 PC이므로 local-demo 로 서약
        scope = build_scope(target, authorized_by="local-demo", authorization_id="demo-1")
        report = run_scan(scope)

        # 전체 JSON 레포트 (취약점 + 조치 가이드)
        out_path = os.path.join(os.getcwd(), "demo-report.json")
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(report.model_dump_json(indent=2))

        s = report.summary
        print(f"\n=== 요약: 총 {s.total}건 ===")
        for sev, count in s.by_severity.items():
            if count:
                print(f"  {sev:8} {count}")
        print("\n=== 발견 항목 ===")
        for f in report.findings:
            print(f"  [{f.severity.value:8}] {f.title}")
            if f.remediation:
                print(f"             ↳ 조치: {f.remediation.summary}")
        print(f"\n[*] 전체 레포트(JSON) 저장: {out_path}")
        print("[*] 감사 로그: .sg/audit.jsonl")
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    main()
