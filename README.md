# Phishing Email Analyzer

피싱 이메일(`.eml`)을 **오프라인으로 트리아지**하는 방어용 분석 도구.
SOC 분석가·침해대응(DFIR) 관점에서 이메일의 위험 지표를 자동 추출하고 위험 점수를 매긴다.

> 방어(분석) 목적 도구입니다. 외부로 공격을 수행하지 않으며, 네트워크 호출 없이 로컬에서만 분석합니다.

## 왜 만들었나 (포트폴리오 배경)

보안관제/침해대응 신입 실무의 핵심 중 하나가 **피싱 이메일 트리아지**다.
TryHackMe SOC Level 1의 *Phishing Analysis* 모듈에서 배운 지표 판단을 직접 코드로 구현해,
"헤더·URL·첨부를 근거로 판정하는" 과정을 자동화했다.

## 기능

- **헤더 분석**: `From`/`Reply-To` 도메인 불일치, 표시이름 스푸핑 탐지
- **인증 결과**: `Authentication-Results`에서 SPF/DKIM/DMARC pass/fail 파싱
- **URL 분석**: IP 기반 호스트, punycode, URL 단축, 과도한 서브도메인, 링크텍스트/실주소 불일치
- **첨부 분석**: SHA256 해시, 위험 확장자(.exe/.js 등), 이중 확장자(`invoice.pdf.exe`), 매크로 오피스
- **위험 점수/판정**: 지표를 가중 합산해 `clean / suspicious / malicious` 판정

## 사용법

```bash
# 표준 라이브러리만 사용 — 별도 설치 불필요 (Python 3.10+)
python -m phishing_analyzer samples/sample_phish.eml          # 텍스트 리포트
python -m phishing_analyzer samples/sample_phish.eml --json   # JSON 출력

# (선택) VirusTotal 평판 조회 — API 키가 있을 때만 동작
set VT_API_KEY=<your_key>        # Windows (PowerShell: $env:VT_API_KEY="...")
python -m phishing_analyzer samples/sample_phish.eml --vt
```
> src 레이아웃이라 실행 시 `PYTHONPATH=src` 를 주거나 `pip install -e .` 로 설치.
> `--vt`는 키가 없으면 조용히 비활성(오프라인 우선). 첨부 해시·URL 도메인 평판을 조회한다.

종료 코드: 악성/의심이면 `1`, clean이면 `0` (파이프라인 연동용).

## 예시 출력

```
판정      : 🔴 MALICIOUS  (점수 100/100)
From      : security@paypal.com <alerts@paypa1-secure.example>
...
[핵심 근거]
  - From/Reply-To 도메인 불일치
  - 표시이름 스푸핑 의심
  - SPF/DMARC 인증 실패
  - 링크 텍스트/실주소 불일치: 'www.paypal.com' → http://192.168.10.44/...
  - 위험 첨부: invoice.pdf.exe
```

## 구조

```
src/phishing_analyzer/
├── analyzer.py     # 이메일 파싱 + 지표 종합 + 점수
├── indicators.py   # 헤더/URL/첨부 판정 로직
├── report.py       # 텍스트/JSON 리포트
└── __main__.py     # CLI
samples/            # 테스트용 합성 샘플
tests/              # unittest (외부 의존성 없음)
```

## 테스트

```bash
python -m unittest discover -s tests -v
```

## 향후 개선

- VirusTotal / URLhaus API 연동(선택, API 키 필요)
- 이메일 본문 언어·긴급성 키워드 스코어링
- Wazuh/SIEM 연동으로 자동 트리아지 (→ mini-soc-homelab 프로젝트와 결합)

## 트러블슈팅

- Windows 콘솔(cp949)에서 한글/이모지 깨짐 → 도구가 출력 스트림을 UTF-8로 재설정하므로 정상 동작.

## 윤리

허가된 본인/조직 메일 분석에만 사용. 분석 목적의 방어 도구다.
