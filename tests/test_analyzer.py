# -*- coding: utf-8 -*-
"""phishing_analyzer 단위 테스트 (stdlib unittest, 외부 의존성 없음)."""

import sys
import unittest
from pathlib import Path

# src 레이아웃을 import 경로에 추가 (설치 없이 테스트)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from phishing_analyzer import analyze_bytes, analyze_file  # noqa: E402
from phishing_analyzer import indicators as ind  # noqa: E402

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "sample_phish.eml"

CLEAN_EML = (
    b"From: Alice <alice@example.com>\r\n"
    b"To: bob@example.com\r\n"
    b"Subject: Lunch tomorrow?\r\n"
    b"Authentication-Results: mx; spf=pass dkim=pass dmarc=pass\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"Hi Bob, see you at noon. https://example.com/menu\r\n"
)


class IndicatorTests(unittest.TestCase):
    def test_parse_address(self):
        display, addr = ind.parse_address('"Sec" <a@b.com>')
        self.assertEqual(display, "Sec")
        self.assertEqual(addr, "a@b.com")

    def test_from_replyto_mismatch(self):
        self.assertTrue(ind.check_from_replyto_mismatch("a@paypal.com", "x@evil.com"))
        self.assertFalse(ind.check_from_replyto_mismatch("a@paypal.com", "b@paypal.com"))
        self.assertFalse(ind.check_from_replyto_mismatch("a@paypal.com", ""))

    def test_display_name_spoof(self):
        self.assertTrue(ind.check_display_name_spoof("security@paypal.com", "x@evil.example"))
        self.assertFalse(ind.check_display_name_spoof("Alice", "alice@example.com"))

    def test_auth_results(self):
        res = ind.parse_auth_results("mx; spf=fail dkim=none dmarc=fail")
        self.assertEqual(res["spf"], "fail")
        self.assertEqual(res["dmarc"], "fail")

    def test_classify_url_ip_and_shortener(self):
        self.assertIn("ip_host", ind.classify_url("http://10.0.0.1/login"))
        self.assertIn("shortener", ind.classify_url("http://bit.ly/abc"))
        self.assertEqual(ind.classify_url("https://example.com/ok"), [])

    def test_dangerous_attachment_double_extension(self):
        info = ind.classify_attachment("invoice.pdf.exe", b"x")
        self.assertEqual(info["risk"], "dangerous")
        self.assertTrue(info["double_extension"])
        self.assertEqual(len(info["sha256"]), 64)


class AnalyzerTests(unittest.TestCase):
    def test_clean_email(self):
        analysis = analyze_bytes(CLEAN_EML)
        self.assertEqual(analysis.verdict, "clean")
        self.assertEqual(analysis.score, 0)

    def test_sample_phish_is_flagged(self):
        self.assertTrue(SAMPLE.exists(), "샘플 .eml이 있어야 함")
        analysis = analyze_file(SAMPLE)
        self.assertEqual(analysis.verdict, "malicious")
        self.assertGreaterEqual(analysis.score, 60)
        # 핵심 지표들이 잡혔는지 확인
        joined = " ".join(analysis.findings)
        self.assertIn("Reply-To", joined)
        self.assertIn("스푸핑", joined)
        self.assertTrue(any(a["risk"] == "dangerous" for a in analysis.attachments))
        self.assertTrue(any(u["flags"] for u in analysis.urls))


if __name__ == "__main__":
    unittest.main(verbosity=2)
