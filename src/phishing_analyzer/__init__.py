# -*- coding: utf-8 -*-
"""피싱 이메일 분석기 — SOC/침해대응 트리아지용 방어 도구."""

from .analyzer import EmailAnalysis, analyze_file, analyze_bytes

__all__ = ["EmailAnalysis", "analyze_file", "analyze_bytes"]
__version__ = "0.1.0"
