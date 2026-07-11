# -*- coding: utf-8 -*-
"""분석 결과를 사람이 읽는 리포트 / JSON으로 포맷."""

import json

_VERDICT_LABEL = {
    "clean": "🟢 CLEAN",
    "suspicious": "🟡 SUSPICIOUS",
    "malicious": "🔴 MALICIOUS",
}


def to_json(analysis, indent=2):
    """분석 결과를 JSON 문자열로 반환."""
    return json.dumps(analysis.to_dict(), ensure_ascii=False, indent=indent)


def to_text(analysis):
    """분석 결과를 트리아지용 텍스트 리포트로 반환."""
    lines = []
    lines.append("=" * 60)
    lines.append("피싱 이메일 분석 리포트")
    lines.append("=" * 60)
    lines.append(f"판정      : {_VERDICT_LABEL.get(analysis.verdict, analysis.verdict)}  (점수 {analysis.score}/100)")
    lines.append(f"제목      : {analysis.subject}")
    lines.append(f"From      : {analysis.from_display} <{analysis.from_addr}>")
    lines.append(f"Reply-To  : {analysis.reply_to or '-'}")
    auth = analysis.auth_results
    lines.append(f"인증      : SPF={auth.get('spf') or '-'} "
                 f"DKIM={auth.get('dkim') or '-'} DMARC={auth.get('dmarc') or '-'}")
    lines.append("")

    lines.append(f"[URL {len(analysis.urls)}개]")
    for u in analysis.urls:
        mark = "⚠" if u["flags"] else " "
        flags = f"  ({', '.join(u['flags'])})" if u["flags"] else ""
        lines.append(f"  {mark} {u['url']}{flags}")
    lines.append("")

    lines.append(f"[첨부 {len(analysis.attachments)}개]")
    for a in analysis.attachments:
        mark = "⚠" if a["risk"] != "ok" else " "
        lines.append(f"  {mark} {a['filename']}  [{a['risk']}]  "
                     f"{a['size']}B  sha256={a['sha256'][:16]}…")
    lines.append("")

    lines.append("[핵심 근거]")
    if analysis.findings:
        for f in analysis.findings:
            lines.append(f"  - {f}")
    else:
        lines.append("  - 특이 지표 없음")
    lines.append("=" * 60)
    return "\n".join(lines)
