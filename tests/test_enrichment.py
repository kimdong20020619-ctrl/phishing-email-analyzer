# -*- coding: utf-8 -*-
"""enrichment(VirusTotal) 단위 테스트 — 네트워크 호출을 목킹."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from phishing_analyzer.enrichment import VTClient, url_to_id, summarize  # noqa: E402


def _fake_fetch_factory(malicious):
    """endpoint에 상관없이 지정한 malicious 수치를 돌려주는 가짜 fetch."""
    def _fetch(endpoint, api_key, timeout=10):
        return {"data": {"attributes": {"last_analysis_stats": {
            "malicious": malicious, "suspicious": 0, "harmless": 70, "undetected": 5,
        }}}}
    return _fetch


class EnrichmentTests(unittest.TestCase):
    def test_url_to_id_no_padding(self):
        vid = url_to_id("http://example.com/a")
        self.assertNotIn("=", vid)

    def test_disabled_without_key(self):
        client = VTClient(api_key=None, fetch=_fake_fetch_factory(3))
        self.assertFalse(client.enabled)
        self.assertIsNone(client.lookup_file("deadbeef"))

    def test_lookup_file_with_mock(self):
        client = VTClient(api_key="X", fetch=_fake_fetch_factory(5))
        stats = client.lookup_file("a" * 64)
        self.assertEqual(stats["malicious"], 5)
        self.assertEqual(summarize(stats), "악성 5/80")

    def test_lookup_handles_bad_payload(self):
        client = VTClient(api_key="X", fetch=lambda *a, **k: {"unexpected": True})
        self.assertIsNone(client.lookup_domain("evil.example"))

    def test_summarize_none(self):
        self.assertEqual(summarize(None), "조회 안 됨")


if __name__ == "__main__":
    unittest.main(verbosity=2)
