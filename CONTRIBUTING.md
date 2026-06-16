# 기여 가이드 (Contributing)

> 이 저장소는 변경 이력을 자동화하기 위해 **Conventional Commits** 와 **release-please** 를 사용합니다.
> 커밋 메시지 규약을 지켜야 CHANGELOG·릴리스가 올바르게 생성됩니다.

## 1. 브랜치 전략

- `main` — 항상 배포 가능 상태. 직접 푸시 대신 **PR로 머지** (브랜치 보호 권장).
- 작업 브랜치 — `feat/<요약>`, `fix/<요약>`, `docs/<요약>` 등.
- PR은 [PR 템플릿](https://github.com/jjamkong/SecurityGuardrails/blob/main/.github/pull_request_template.md)의 **통제 체크리스트 + DoD**를 채운다.

## 2. Conventional Commits

형식: `type(scope): subject`

| type | 용도 | 버전 영향 (release-please) |
|------|------|---------------------------|
| `feat` | 기능 추가 | minor↑ |
| `fix` | 버그 수정 | patch↑ |
| `docs` | 문서만 변경 | (기본) 릴리스 없음 |
| `refactor` / `perf` | 동작 불변 개선 | patch↑ (설정 시) |
| `test` / `ci` / `build` / `chore` | 보조 변경 | 릴리스 없음 |

- **Breaking change**: 본문에 `BREAKING CHANGE:` 또는 type 뒤 `!` (예: `feat!:`) → major↑ (1.0.0 이전엔 minor↑).
- 예: `feat(scanner): passive 헤더 점검 모듈 추가`, `fix(crawler): 스코프 밖 링크 follow 차단`.

## 3. 변경 이력은 자동

1. `main`에 커밋이 쌓이면 **release-please**가 "release PR"을 생성/갱신한다.
2. 그 PR을 머지하면 `CHANGELOG.md` 갱신 + GitHub Release + 태그(`vX.Y.Z`)가 자동 생성된다.
3. `CHANGELOG.md`는 release-please가 관리하므로 **수동 편집하지 않는다.**

## 4. 통제 규약 (코드 변경 시 필수)

[CLAUDE.md](CLAUDE.md)의 통제 7대 규칙은 회귀 대상이다. PR은 다음을 위반하지 않아야 한다:
승인된 자산만 점검 · 스코프 격리 · 비파괴 기본값 · DoS 금지/속도제한 · 불변 감사로그 · 데이터 보호 · 악용 산출물 금지.

## 5. 로컬 검증 (CI와 동일)

```bash
# 문서 빌드
pip install -r requirements-docs.txt
mkdocs build --strict

# 마크다운 린트 (Node 필요)
npx --yes markdownlint-cli2 "**/*.md"
```

## 6. 보안 하드닝 메모

GitHub Actions는 현재 메이저 태그(`@v4` 등)로 고정되어 있다. 공급망 보안을 더 높이려면
액션을 **커밋 SHA로 고정**(pin)하는 것을 권장한다.
