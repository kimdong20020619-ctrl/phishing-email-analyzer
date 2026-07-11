# -*- coding: utf-8 -*-
"""VirusTotal 선택적 인리치먼트 (방어용 평판 조회).

API 키가 있을 때만 동작한다. 네트워크/키가 없으면 조용히 건너뛴다(오프라인 우선).
테스트 가능하도록 HTTP 호출부(fetch)를 주입할 수 있게 설계했다.
"""

import base64
import json
import os
import urllib.error
import urllib.request

_VT_BASE = "https://www.virustotal.com/api/v3"


def url_to_id(url):
    """VirusTotal URL 식별자(패딩 없는 base64url)."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _default_fetch(endpoint, api_key, timeout=10):
    """실제 VirusTotal GET 호출. 실패 시 None."""
    req = urllib.request.Request(f"{_VT_BASE}/{endpoint}",
                                 headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError):
        return None


class VTClient:
    """VirusTotal v3 조회 클라이언트. fetch 주입으로 테스트 가능."""

    def __init__(self, api_key=None, fetch=None):
        self.api_key = api_key or os.environ.get("VT_API_KEY")
        self._fetch = fetch or _default_fetch

    @property
    def enabled(self):
        return bool(self.api_key)

    def _stats(self, endpoint):
        if not self.enabled:
            return None
        data = self._fetch(endpoint, self.api_key)
        if not data:
            return None
        try:
            attrs = data["data"]["attributes"]
            return attrs.get("last_analysis_stats")
        except (KeyError, TypeError):
            return None

    def lookup_file(self, sha256):
        """파일 해시 평판. {malicious, suspicious, ...} 또는 None."""
        return self._stats(f"files/{sha256}")

    def lookup_domain(self, domain):
        """도메인 평판."""
        return self._stats(f"domains/{domain}")


def summarize(stats):
    """last_analysis_stats를 'malicious/총합' 형태 문자열로."""
    if not stats:
        return "조회 안 됨"
    total = sum(v for v in stats.values() if isinstance(v, int))
    return f"악성 {stats.get('malicious', 0)}/{total}"
