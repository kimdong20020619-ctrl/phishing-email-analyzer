# -*- coding: utf-8 -*-
"""이메일 파싱 + 지표 종합 + 위험 점수 산출."""

from dataclasses import dataclass, field, asdict
from email import policy
from email.parser import BytesParser
from pathlib import Path

from . import indicators as ind

# 위험 점수 가중치 (합산해 verdict 결정)
_WEIGHTS = {
    "from_replyto_mismatch": 20,
    "display_name_spoof": 30,
    "spf_fail": 15,
    "dkim_fail": 10,
    "dmarc_fail": 20,
    "suspicious_url": 15,
    "anchor_mismatch": 20,
    "dangerous_attachment": 40,
    "macro_attachment": 20,
}


@dataclass
class EmailAnalysis:
    """분석 결과 컨테이너."""
    subject: str = ""
    from_display: str = ""
    from_addr: str = ""
    reply_to: str = ""
    auth_results: dict = field(default_factory=dict)
    urls: list = field(default_factory=list)
    anchor_mismatches: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    score: int = 0
    verdict: str = "clean"

    def to_dict(self):
        return asdict(self)


def _verdict_for(score):
    if score >= 60:
        return "malicious"
    if score >= 30:
        return "suspicious"
    return "clean"


def _get_body_text(msg, subtype):
    """지정 subtype(html/plain) 본문을 문자열로 반환. 없으면 빈 문자열."""
    part = msg.get_body(preferencelist=(subtype,))
    if part is None:
        return ""
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def analyze_bytes(raw):
    """원시 .eml 바이트열을 분석해 EmailAnalysis 반환."""
    assert isinstance(raw, (bytes, bytearray)), "raw는 bytes여야 합니다"
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    from_display, from_addr = ind.parse_address(msg["From"])
    _, reply_to = ind.parse_address(msg["Reply-To"])
    auth = ind.parse_auth_results(msg["Authentication-Results"])

    html_body = _get_body_text(msg, "html")
    text_body = _get_body_text(msg, "plain")
    urls = ind.extract_urls(html_body, text_body)
    anchor_mismatches = ind.check_anchor_mismatch(html_body)

    attachments = []
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        attachments.append(ind.classify_attachment(part.get_filename(), payload))

    analysis = EmailAnalysis(
        subject=str(msg["Subject"] or ""),
        from_display=from_display,
        from_addr=from_addr,
        reply_to=reply_to,
        auth_results=auth,
        urls=[{"url": u, "flags": ind.classify_url(u)} for u in urls],
        anchor_mismatches=anchor_mismatches,
        attachments=attachments,
    )
    _score(analysis)
    return analysis


def analyze_file(path):
    """.eml 파일 경로를 받아 분석한다."""
    data = Path(path).read_bytes()
    return analyze_bytes(data)


def _score(analysis):
    """지표를 근거(findings)와 점수로 환산해 analysis를 채운다."""
    findings = []
    score = 0

    if ind.check_from_replyto_mismatch(analysis.from_addr, analysis.reply_to):
        score += _WEIGHTS["from_replyto_mismatch"]
        findings.append(f"From({analysis.from_addr})과 Reply-To({analysis.reply_to}) 도메인 불일치")

    if ind.check_display_name_spoof(analysis.from_display, analysis.from_addr):
        score += _WEIGHTS["display_name_spoof"]
        findings.append(f"표시이름 스푸핑 의심: '{analysis.from_display}' vs {analysis.from_addr}")

    for mech, weight_key in (("spf", "spf_fail"), ("dkim", "dkim_fail"), ("dmarc", "dmarc_fail")):
        if analysis.auth_results.get(mech) == "fail":
            score += _WEIGHTS[weight_key]
            findings.append(f"{mech.upper()} 인증 실패")

    suspicious_urls = [u for u in analysis.urls if u["flags"]]
    if suspicious_urls:
        score += _WEIGHTS["suspicious_url"]
        for u in suspicious_urls:
            findings.append(f"의심 URL: {u['url']} ({', '.join(u['flags'])})")

    if analysis.anchor_mismatches:
        score += _WEIGHTS["anchor_mismatch"]
        for m in analysis.anchor_mismatches:
            findings.append(f"링크 텍스트/실주소 불일치: 표시 '{m['shown']}' → {m['href']}")

    for att in analysis.attachments:
        if att["risk"] == "dangerous":
            score += _WEIGHTS["dangerous_attachment"]
            findings.append(f"위험 첨부: {att['filename']} (sha256 {att['sha256'][:16]}…)")
        elif att["risk"] == "macro":
            score += _WEIGHTS["macro_attachment"]
            findings.append(f"매크로 가능 첨부: {att['filename']}")

    analysis.findings = findings
    analysis.score = min(score, 100)
    analysis.verdict = _verdict_for(analysis.score)
