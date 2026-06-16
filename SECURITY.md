# 보안 정책 (Security Policy)

## 책임 있는 사용 (Acceptable Use)

SecurityGuardrails는 **합법·방어 목적의 웹 취약점 점검** 도구입니다. 다음을 전제로만 사용합니다:

- **소유**하거나 **서면 점검 승인(Scope Authorization)** 을 받은 자산만 점검한다.
- 점검은 **비파괴 기본값 · 속도제한**을 지키며, 서비스 마비(DoS)를 유발하지 않는다.
- 모든 점검은 **감사 로그**로 추적 가능해야 하며, 수집 증거의 민감정보는 보호·파기한다.
- 산출되는 조치 가이드는 **방어·수정 관점**으로만 작성한다(무기화된 익스플로잇 배포 금지).

무단 스캔·침해는 위법이며, 본 프로젝트의 목적과 무관합니다. 상세 대원칙: [PLAN.md](PLAN.md) §0.

## 취약점 신고 (Reporting a Vulnerability)

이 **저장소/도구 자체**의 보안 문제를 발견하면:

1. 공개 이슈로 올리지 말고, GitHub **Security Advisory**(Repository → Security → *Report a vulnerability*)로 비공개 신고하거나 메인테이너에게 비공개로 연락한다.
2. 재현 절차·영향·가능하면 PoC를 포함한다.
3. 합리적인 기간 동안 비공개 조정(coordinated disclosure)에 협조한다.

## 비밀·자격증명

- 비밀(`.env`, 키, 인증서), 스캔 증거·결과는 **커밋하지 않는다** ([.gitignore](https://github.com/jjamkong/SecurityGuardrails/blob/main/.gitignore) 적용).
- CI/CD는 최소 권한 토큰으로 동작한다(워크플로우별 `permissions` 명시).
