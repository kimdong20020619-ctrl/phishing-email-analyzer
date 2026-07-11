# -*- coding: utf-8 -*-
"""CLI 진입점: python -m phishing_analyzer <파일.eml> [--json]"""

import argparse
import re
import sys

from .analyzer import analyze_file
from . import report
from .enrichment import VTClient, summarize


def _domain_of_url(url):
    host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0]
    return host.split(":")[0].split("@")[-1].lower()


def _vt_section(analysis, client):
    """VirusTotal 평판 조회 결과 문자열. 비활성/무결과면 안내."""
    if not client.enabled:
        return "[VirusTotal] 비활성 (VT_API_KEY 미설정)"
    lines = ["[VirusTotal 평판]"]
    for att in analysis.attachments:
        lines.append(f"  첨부 {att['filename']}: {summarize(client.lookup_file(att['sha256']))}")
    seen = set()
    for u in analysis.urls:
        dom = _domain_of_url(u["url"])
        if dom and dom not in seen:
            seen.add(dom)
            lines.append(f"  도메인 {dom}: {summarize(client.lookup_domain(dom))}")
    return "\n".join(lines)


def _force_utf8_output():
    """Windows 콘솔(cp949)에서도 한글·기호가 깨지지 않도록 UTF-8로 재설정."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(encoding="utf-8", errors="replace")


def main(argv=None):
    _force_utf8_output()
    parser = argparse.ArgumentParser(
        prog="phishing_analyzer",
        description="피싱 이메일(.eml) 오프라인 트리아지 분석기 (방어용).",
    )
    parser.add_argument("eml", help="분석할 .eml 파일 경로")
    parser.add_argument("--json", action="store_true", help="JSON으로 출력")
    parser.add_argument("--vt", action="store_true",
                        help="VirusTotal 평판 조회 (VT_API_KEY 환경변수 필요)")
    args = parser.parse_args(argv)

    try:
        analysis = analyze_file(args.eml)
    except FileNotFoundError:
        print(f"[오류] 파일을 찾을 수 없습니다: {args.eml}", file=sys.stderr)
        return 2

    print(report.to_json(analysis) if args.json else report.to_text(analysis))
    if args.vt and not args.json:
        print(_vt_section(analysis, VTClient()))
    # 악성/의심이면 non-zero 종료코드 → 파이프라인에서 활용 가능
    return 1 if analysis.verdict != "clean" else 0


if __name__ == "__main__":
    sys.exit(main())
