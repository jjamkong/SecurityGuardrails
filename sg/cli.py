from __future__ import annotations

import argparse
import sys
from uuid import uuid4

from .config import Settings
from .models import Intensity
from .scanner import run_scan
from .scope import AuthorizationError, build_scope

_BANNER = (
    "⚠️  SecurityGuardrails — 본인 소유이거나 서면 점검 승인을 받은 자산에만 사용하세요.\n"
    "    무단 스캔은 위법입니다. (PLAN.md §0 / CLAUDE.md 통제 규약)\n"
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sg", description="합법·방어용 웹 취약점 Passive 스캐너 (MVP)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="URL을 Passive 점검한다")
    scan.add_argument("url", help="점검 대상 URL (예: https://example.internal)")
    scan.add_argument("--authorized-by", required=True, help="점검 승인자(필수)")
    scan.add_argument("--scope-id", default=None, help="점검 승인 ID (미지정 시 생성)")
    scan.add_argument(
        "--allow-host",
        action="append",
        default=None,
        help="추가 허용 호스트(반복 가능). 미지정 시 대상 호스트만 허용",
    )
    scan.add_argument(
        "--intensity",
        choices=[i.value for i in Intensity],
        default=Intensity.passive.value,
        help="점검 강도 (MVP는 passive만 실행)",
    )
    scan.add_argument("--rps", type=float, default=None, help="초당 요청 상한(속도제한)")
    scan.add_argument("--timeout", type=float, default=None, help="요청 타임아웃(초)")
    scan.add_argument("--out", default=None, help="JSON 레포트 저장 경로")
    return parser


def _run_scan_cmd(args: argparse.Namespace) -> int:
    sys.stderr.write(_BANNER)
    intensity = Intensity(args.intensity)
    if intensity is not Intensity.passive:
        sys.stderr.write("ℹ️  MVP는 passive 점검만 수행합니다 (Active는 Sprint 2).\n")

    settings = Settings()
    if args.rps is not None:
        if args.rps <= 0:
            sys.stderr.write("⛔ --rps는 0보다 커야 합니다 (속도제한 무력화 방지).\n")
            return 2
        settings.max_requests_per_second = args.rps
    if args.timeout is not None:
        if args.timeout <= 0:
            sys.stderr.write("⛔ --timeout은 0보다 커야 합니다.\n")
            return 2
        settings.request_timeout = args.timeout

    # 스킴 누락 시 https로 정규화
    url = args.url
    if "://" not in url:
        url = f"https://{url}"
        sys.stderr.write(f"ℹ️  스킴이 없어 https로 가정합니다: {url}\n")

    scope = build_scope(
        target=url,
        authorized_by=args.authorized_by,
        authorization_id=args.scope_id or f"adhoc-{uuid4().hex[:8]}",
        allowed_hosts=args.allow_host,
        intensity=intensity,
    )

    try:
        result = run_scan(scope, settings)
    except AuthorizationError as exc:
        sys.stderr.write(f"⛔ 승인/스코프 거부: {exc}\n")
        return 2

    payload = result.model_dump_json(indent=2)
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(payload)
            sys.stderr.write(f"📄 레포트 저장: {args.out}\n")
        except OSError as exc:
            sys.stderr.write(f"⚠️ 레포트 저장 실패({exc}). stdout로 출력합니다.\n")
            sys.stdout.write(payload + "\n")
    else:
        sys.stdout.write(payload + "\n")

    s = result.summary
    sys.stderr.write(
        f"\n✅ 완료: {s.total}건 — "
        + ", ".join(f"{k} {v}" for k, v in s.by_severity.items() if v)
        + (f"\n⚠️ 오류 {len(result.errors)}건" if result.errors else "")
        + "\n"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan_cmd(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
