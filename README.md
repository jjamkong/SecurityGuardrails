# SecurityGuardrails

> **URL을 입력하면 해당 사이트를 점검하여 ① 취약점 레포트 와 ② 취약점별 조치 가이드 를 산출하는 합법·방어용 웹 취약점 분석 시스템.**

[![CI](https://github.com/jjamkong/SecurityGuardrails/actions/workflows/ci.yml/badge.svg)](https://github.com/jjamkong/SecurityGuardrails/actions/workflows/ci.yml)
[![Deploy Docs](https://github.com/jjamkong/SecurityGuardrails/actions/workflows/docs-deploy.yml/badge.svg)](https://github.com/jjamkong/SecurityGuardrails/actions/workflows/docs-deploy.yml)
[![Release Please](https://github.com/jjamkong/SecurityGuardrails/actions/workflows/release-please.yml/badge.svg)](https://github.com/jjamkong/SecurityGuardrails/actions/workflows/release-please.yml)

## ⚠️ 승인된 점검만 — 합법·방어 목적 전용

이 프로젝트는 **본인 소유이거나 서면 점검 승인(Scope Authorization)을 받은 자산**에 대해서만 사용합니다.
무단 스캔은 위법이며, 도구는 비파괴·속도제한·감사로그 등 안전장치를 전제로 설계됩니다.
자세한 대원칙은 [PLAN.md](PLAN.md) §0, 운영 규약은 [CLAUDE.md](CLAUDE.md) 를 참고하세요.

## 현재 상태

**계획 단계.** 저장소에는 기획·역할·운영 문서만 있으며 **애플리케이션 소스 코드는 아직 없습니다.**
기술 스택·로드맵·데이터 모델은 모두 제안(proposed) 상태이며 출처는 항상 `PLAN.md` 입니다.

## 문서

| 문서 | 내용 |
|------|------|
| [PLAN.md](PLAN.md) | 마스터 기획서 — 목표·기능요건·취약점 분석 절차(S0~S7)·역할 오케스트레이션·로드맵 |
| [CLAUDE.md](CLAUDE.md) | 운영 규약 — 명료화·통제 거버넌스 |
| [harness/README.md](harness/README.md) | 역할별 상세 JD 인덱스 (프로세스 기반 자유도) |
| [CHANGELOG.md](CHANGELOG.md) | 변경 이력 (release-please 자동 관리) |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 기여·커밋·브랜치 규약 |
| [SECURITY.md](SECURITY.md) | 보안 정책 / 책임 있는 사용 |

📖 **렌더링된 문서 사이트:** <https://jjamkong.github.io/SecurityGuardrails/> (main 배포 후 활성화)

## 버전 관리 · CI/CD (이력관리)

모든 변경은 Git으로 버전관리하며, [Conventional Commits](https://www.conventionalcommits.org/ko/)를 사용합니다.

| 파이프라인 | 트리거 | 동작 |
|------------|--------|------|
| **CI** ([ci.yml](https://github.com/jjamkong/SecurityGuardrails/blob/main/.github/workflows/ci.yml)) | PR · `main` push | 마크다운 린트 + 내부 링크 체크 + MkDocs 빌드 스모크 |
| **CD — 문서 배포** ([docs-deploy.yml](https://github.com/jjamkong/SecurityGuardrails/blob/main/.github/workflows/docs-deploy.yml)) | `main` push | MkDocs Material 사이트를 GitHub Pages로 **지속 배포** |
| **릴리스 자동화** ([release-please.yml](https://github.com/jjamkong/SecurityGuardrails/blob/main/.github/workflows/release-please.yml)) | `main` push | 커밋 분석 → 릴리스 PR → 머지 시 **CHANGELOG·Release·태그 자동 생성** |

## ⚙️ 최초 1회 수동 설정 (필요)

이 두 가지는 저장소 설정이라 코드로 자동화되지 않습니다:

1. **GitHub Pages 소스 지정** — Settings → Pages → *Build and deployment* → Source를 **GitHub Actions**로 설정. (그래야 `docs-deploy`가 동작)
2. **첫 배포 트리거** — 위 설정 후 *Actions 탭 → Deploy Docs → Run workflow*(`workflow_dispatch`)로 1회 실행하면 첫 사이트가 게시됩니다(코드 변경 불필요).
3. **(권장) 브랜치 보호** — Settings → Branches → `main` 보호 규칙: PR 필수 + CI 통과 필수.

> ⚠️ 브랜치 보호에서 "CI 통과 필수"를 켜면, release-please가 기본 `GITHUB_TOKEN`으로 연 릴리스 PR에는 CI 체크가 붙지 않아 머지가 막힐 수 있습니다. 릴리스 PR을 보호 예외로 두거나, PAT/GitHub App 토큰을 워크플로에 주입하세요.

## 웹 UI (브라우저에서 도메인 입력 → 결과 표)

CLI 대신 웹 폼으로 점검할 수 있습니다. **무단 스캔 방지**를 위해 두 가지가 모두 설정돼야 동작합니다(fail-closed):

- `SG_API_KEY` — 접근 키(아무나 못 돌림)
- `SG_AUTHORIZED_DOMAINS` — **점검 허용 도메인**(쉼표 구분). 이 도메인/서브도메인만 점검 가능, **그 외 도메인은 403 거부**.

```powershell
$env:SG_API_KEY = "원하는-키"
$env:SG_AUTHORIZED_DOMAINS = "next-securities.com,mycompany.com"
uvicorn sg.api:app --host 127.0.0.1 --port 8000
# 브라우저에서 http://127.0.0.1:8000 접속 → 대상 URL + 접근 키 입력 → 점검 실행
```

> ⚠️ 이 UI는 **조직이 승인한 도메인을 권한 있는 담당자가** 점검하는 용도입니다.
> "아무나 아무 도메인이나" 스캔하는 공개 서비스로 노출하지 마세요(무단 스캔 = 위법).
> 외부 공개가 필요하면 인증/접근통제를 반드시 앞단에 두세요.

## 로컬에서 문서 미리보기

```bash
pip install -r requirements-docs.txt
mkdocs serve     # http://127.0.0.1:8000
```

## 라이선스

미정 (TBD). 정해지면 `LICENSE` 추가 예정.
