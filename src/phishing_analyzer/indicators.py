# -*- coding: utf-8 -*-
"""피싱 지표(indicator) 추출·판정 로직.

헤더/URL/첨부를 분석해 의심 지표를 산출한다. 외부 네트워크 호출은 하지 않는다
(오프라인 트리아지). VirusTotal 등 온라인 조회는 상위 계층에서 선택적으로 붙인다.
"""

import hashlib
import re
from email.headerregistry import Address
from email.utils import getaddresses

# 실행 파일·스크립트 등 이메일 첨부로 위험한 확장자
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse",
    ".vbs", ".vbe", ".wsf", ".hta", ".ps1", ".jar", ".lnk", ".msi",
    ".dll", ".reg", ".iso", ".img",
}

# 매크로 포함 가능 오피스 확장자 (주의 대상)
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}

# 대표적인 URL 단축 서비스 도메인
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "cutt.ly", "rebrand.ly", "shorturl.at",
}

_URL_RE = re.compile(r"https?://[^\s\"'<>()]+", re.IGNORECASE)
_HREF_RE = re.compile(r"href\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_ANCHOR_RE = re.compile(r"<a\b[^>]*href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
                        re.IGNORECASE | re.DOTALL)
_IPV4_HOST_RE = re.compile(r"^https?://(\d{1,3}\.){3}\d{1,3}(?::\d+)?(/|$)", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")


def parse_address(header_value):
    """헤더 문자열에서 (표시이름, 이메일주소)를 뽑는다. 없으면 ('', '')."""
    if not header_value:
        return "", ""
    addrs = getaddresses([str(header_value)])
    if not addrs:
        return "", ""
    display, addr = addrs[0]
    return display.strip(), addr.strip().lower()


def domain_of(email_addr):
    """이메일 주소의 도메인 부분을 소문자로 반환."""
    if not email_addr or "@" not in email_addr:
        return ""
    return email_addr.rsplit("@", 1)[1].lower()


def check_from_replyto_mismatch(from_addr, replyto_addr):
    """From과 Reply-To의 도메인이 다르면 True (회신 가로채기 의심)."""
    if not replyto_addr:
        return False
    return domain_of(from_addr) != domain_of(replyto_addr)


def check_display_name_spoof(display_name, actual_addr):
    """표시이름에 실제 발신 도메인과 다른 이메일/도메인이 박혀 있으면 True.

    예: 표시이름 "security@paypal.com" 인데 실제 주소는 attacker@evil.com.
    """
    if not display_name:
        return False
    embedded = re.findall(r"[\w.+-]+@([\w.-]+)", display_name)
    actual_domain = domain_of(actual_addr)
    for dom in embedded:
        if actual_domain and dom.lower() != actual_domain:
            return True
    return False


def parse_auth_results(header_value):
    """Authentication-Results 헤더에서 spf/dkim/dmarc 결과를 뽑는다."""
    result = {"spf": None, "dkim": None, "dmarc": None}
    if not header_value:
        return result
    text = str(header_value).lower()
    for mech in result:
        match = re.search(mech + r"=(\w+)", text)
        if match:
            result[mech] = match.group(1)
    return result


def extract_urls(html_body, text_body):
    """본문(HTML+텍스트)에서 URL 목록을 중복 제거해 반환."""
    urls = []
    for body in (html_body or "", text_body or ""):
        urls.extend(_URL_RE.findall(body))
        urls.extend(_HREF_RE.findall(body))
    seen = set()
    unique = []
    for url in urls:
        url = url.rstrip(".,);]")
        if url.lower().startswith("http") and url not in seen:
            seen.add(url)
            unique.append(url)
    return unique


def classify_url(url):
    """단일 URL의 의심 플래그 목록을 반환."""
    flags = []
    if _IPV4_HOST_RE.match(url):
        flags.append("ip_host")
    if "xn--" in url.lower():
        flags.append("punycode")
    host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0].lower()
    host = host.split(":")[0]
    if host in SHORTENER_DOMAINS:
        flags.append("shortener")
    if host.count(".") >= 4:
        flags.append("many_subdomains")
    if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
        flags.append("userinfo_in_host")
    return flags


def check_anchor_mismatch(html_body):
    """<a> 표시텍스트에 보이는 도메인과 실제 href 도메인이 다른 경우를 찾는다."""
    mismatches = []
    if not html_body:
        return mismatches
    for href, text in _ANCHOR_RE.findall(html_body):
        visible = _TAG_RE.sub("", text)
        shown = re.findall(r"[\w.-]+\.[a-z]{2,}", visible.lower())
        if not shown:
            continue
        href_host = re.sub(r"^https?://", "", href, flags=re.IGNORECASE).split("/")[0].lower()
        if href_host and all(s not in href_host and href_host not in s for s in shown):
            mismatches.append({"shown": shown[0], "href": href})
    return mismatches


def hash_bytes(data):
    """바이트열의 SHA256 해시(hex)를 반환."""
    return hashlib.sha256(data).hexdigest()


def classify_attachment(filename, payload):
    """첨부 하나에 대한 정보·위험도 dict를 반환."""
    name = (filename or "unknown").strip()
    lower = name.lower()
    ext = ""
    if "." in lower:
        ext = lower[lower.rfind("."):]
    danger = "dangerous" if ext in DANGEROUS_EXTENSIONS else (
        "macro" if ext in MACRO_EXTENSIONS else "ok")
    double_ext = bool(re.search(r"\.\w{2,4}\.(exe|scr|js|vbs|bat|cmd)$", lower))
    return {
        "filename": name,
        "extension": ext,
        "size": len(payload),
        "sha256": hash_bytes(payload),
        "risk": "dangerous" if double_ext else danger,
        "double_extension": double_ext,
    }
