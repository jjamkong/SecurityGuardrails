# Sprint 1 백로그 — Phase 1 (승인/스코프 + Passive 점검 + 최소 레포트)

> 상위: [PLAN.md](../PLAN.md) §8 Phase 1 · 절차 [§3](../PLAN.md) S0·S2·S6 · 백로그 규약: [README.md](README.md)

## 🎯 Sprint Goal

**승인된 단일 URL에 대해 Passive(무해) 점검을 수행하고, 취약점별 조치 가이드가 포함된 JSON 레포트를 생성하는 E2E 한 줄기를 동작시킨다.**
(`scan <URL> --authorized-by ...` → 스코프 검증 → 헤더·TLS·쿠키·정보노출 점검 → JSON 레포트 + 조치 가이드)

스택: **Python (FastAPI)** · 점검 강도: **Passive 만** · 능동(Active) 점검은 Sprint 2.

## ✅ Definition of Ready (착수 전)

- 대상 취약점 유형·예상 탐지 시그니처·테스트 케이스(취약/정상)·승인 스코프가 스토리에 정의됨.

## ✅ Definition of Done (완료)

- 코드 + 단위 테스트 통과 · 린트/타입 통과(ruff·mypy) · CI green
- 정상 사이트에서 **오탐 없음** 케이스 1건 이상 통과
- 발견 항목에 **조치 가이드 포함** · 문서 갱신
- **안전장치 회귀 통과**(스코프 격리·비파괴(GET/HEAD)·속도제한·감사로그)

---

## Epic 개요

| Epic | 내용 | 절차 |
|------|------|------|
| **E1. 골격** | Python/FastAPI 스캐폴딩·CLI·HTTP 클라이언트·CI 통합 | — |
| **E2. 승인·스코프** | 스코프 모델·승인 게이트·스코프 격리 | S0 |
| **E3. Passive 점검** | 헤더·TLS·쿠키·정보노출 점검 | S2 |
| **E4. 레포트·조치 가이드** | Finding 모델·조치 KB·JSON 레포트 | S6 |
| **E5. 안전장치(횡단)** | 속도제한·감사로그 | 횡단 |

## 스토리 요약

| ID | Epic | 제목 | 우선 | SP | 담당 |
|----|------|------|------|----|------|
| SG-1 | E1 | 프로젝트 스캐폴딩 (패키지·설정·pyproject) | Must | 3 | BE/ARC |
| SG-2 | E1 | CLI 진입점 + 안전 HTTP 클라이언트(GET/HEAD 전용) | Must | 3 | BE |
| SG-3 | E1 | 테스트·린트·CI 통합 (pytest·ruff·mypy) | Must | 3 | BE/QA |
| SG-4 | E2 | 스코프 정의 모델 (대상·허용호스트·강도·승인·만료) | Must | 2 | ARC/CMP |
| SG-5 | E2 | 승인 게이트 — 미승인/만료 시 스캔 차단 | Must | 5 | SEC/CMP |
| SG-6 | E2 | 스코프 격리 — 허용 호스트 밖 요청 거부 | Must | 3 | BE/SEC |
| SG-7 | E3 | 보안 헤더 점검 (CSP·HSTS·XFO·XCTO·Referrer) | Must | 5 | SEC |
| SG-8 | E3 | TLS/인증서 점검 (평문·만료·자가서명) | Must | 5 | SEC |
| SG-9 | E3 | 쿠키 플래그 점검 (Secure·HttpOnly·SameSite) | Must | 3 | SEC |
| SG-10 | E3 | 정보 노출 점검 (배너·노출 경로 — 비파괴 GET) | Should | 5 | SEC |
| SG-11 | E4 | Finding 모델 + 심각도·CWE·OWASP 매핑 | Must | 3 | RPT |
| SG-12 | E4 | 조치 가이드 KB (유형별 무엇/왜/어떻게/검증) | Must | 5 | RPT/SEC |
| SG-13 | E4 | JSON 레포트 생성 + 심각도 요약 | Must | 3 | RPT |
| SG-14 | E5 | 속도제한·동시성 상한·백오프 (DoS 금지) | Must | 3 | BE/OPS |
| SG-15 | E5 | 감사 로그 (actor·시각·대상·강도, append-only) | Must | 3 | OPS |

**합계 ≈ 54 SP** (2주 기준 도전적 — `SG-10`은 Should, 여력 부족 시 Sprint 2로 이월).

---

## 상세 스토리 (인수조건)

### SG-4 · 스코프 정의 모델  `[S0]` `Must` `2SP`

- **As a** 보안 담당자, **I want** 점검 대상·허용 호스트·강도·승인 정보를 구조화해, **so that** 승인 범위가 코드로 강제된다.
- **AC**
  - Given 대상 URL과 승인자/승인ID, When 스코프를 생성하면, Then `allowed_hosts` 기본값은 대상 호스트가 된다.
  - 강도는 `passive|safe_active|full` 중 하나, 기본 `passive`.
  - `expires_at` 지정 시 만료 판정이 가능하다.
- **통제**: ①승인된 자산만 점검.

### SG-5 · 승인 게이트  `[S0]` `Must` `5SP`

- **As a** 시스템, **I want** 스캔 실행 전 승인을 검증해, **so that** 미승인 대상은 절대 점검되지 않는다.
- **AC**
  - Given 승인 정보 누락/만료, When 스캔을 시도하면, Then `AuthorizationError`로 **차단**된다(점검 0건).
  - Given 대상 호스트가 `allowed_hosts`에 없음, When 스캔 시도, Then 차단된다.
  - 정상 승인 시에만 파이프라인이 진행된다.
- **통제**: ①승인 ②스코프 격리. **테스트**: 차단/통과 양쪽.

### SG-6 · 스코프 격리  `[S0]` `Must` `3SP`

- **AC**: 점검 중 생성되는 모든 추가 요청 URL은 `is_in_scope()` 통과 시에만 발사. 범위 밖 링크/경로는 follow 금지.
- **통제**: ②스코프 격리.

### SG-7 · 보안 헤더 점검  `[S2]` `Must` `5SP`

- **AC**
  - Given 응답에 `Strict-Transport-Security` 없음, Then HSTS 누락 finding(중간, CWE-693) 생성.
  - `Content-Security-Policy`·`X-Frame-Options`·`X-Content-Type-Options`·`Referrer-Policy` 각각 누락 시 finding.
  - Given 모든 권장 헤더 존재, Then **finding 없음(오탐 0)**.
  - 각 finding에 조치 가이드 연결.

### SG-8 · TLS/인증서 점검  `[S2]` `Must` `5SP`

- **AC**
  - Given 대상이 `http://`(평문), Then 평문 전송 finding(높음, CWE-319).
  - Given 인증서 만료/만료임박(≤14일), Then finding(높음/중간).
  - Given 자가서명/검증 실패, Then finding(중간, CWE-295).
  - Given 유효한 HTTPS, Then TLS finding 없음.
- **비고**: 인증서 자체 분석을 위해 비검증 연결로 cert를 수집(검증은 별도 판정).

### SG-9 · 쿠키 플래그 점검  `[S2]` `Must` `3SP`

- **AC**: `Set-Cookie`에 `Secure`/`HttpOnly`/`SameSite` 누락 시 각각 finding(중간/낮음, CWE-614/1004). 모두 충족 시 finding 없음.

### SG-10 · 정보 노출 점검  `[S2]` `Should` `5SP`

- **AC**
  - 잘 알려진 노출 경로(`/.git/HEAD`, `/.env` 등)를 **GET(비파괴)** 으로만 확인, 200 + 시그니처 일치 시 finding(높음, CWE-538).
  - `Server`/`X-Powered-By` 상세 배너 노출 시 finding(정보).
  - 모든 추가 요청은 **스코프 내**에서만(SG-6 의존).
- **통제**: ②스코프 ③비파괴.

### SG-12 · 조치 가이드 KB  `[S6]` `Must` `5SP`

- **AC**: 발견 유형(remediation_key)마다 `요약·왜 위험·어떻게 고침(단계)·검증 방법·참고`를 제공. **방어/수정 관점만**(무기화 익스플로잇 금지). 레포트 생성 시 finding에 자동 결합.
- **통제**: ⑦악용 산출물 금지.

### SG-13 · JSON 레포트  `[S6]` `Must` `3SP`

- **AC**: 레포트에 스캔 메타(scan_id·대상·강도·시각·승인ID·actor) + findings(조치 가이드 포함) + 심각도별 요약 카운트 포함. 안정적 직렬화(스키마 고정).

### SG-14 · 속도제한  `[횡단]` `Must` `3SP`

- **AC**: 초당 요청 상한(기본 5 rps) + 요청 간 최소 간격. 부하/DoS 유발 금지. 설정으로 조정.
- **통제**: ④DoS 금지.

### SG-15 · 감사 로그  `[횡단]` `Must` `3SP`

- **AC**: 스캔 시작/종료 시 `actor·시각·대상·강도·승인ID`를 append-only(JSONL)로 기록. 로그는 VCS 제외.
- **통제**: ⑤감사 로그.

---

## 측정 (Sprint Review 기준)

- **탐지율**: 의도적 취약 대상(로컬 테스트 서버/취약앱)에서 주입한 결함을 탐지하는 비율.
- **오탐율**: 정상(견고하게 설정된) 대상에서 finding 0 유지.
- **안전장치 회귀**: 미승인 차단·스코프 격리·GET/HEAD 전용·속도제한·감사로그 전부 통과.
