# 백로그 (Backlog)

> 스프린트별 Epic → Story 백로그. 상위: [PLAN.md](../PLAN.md) §5(애자일)·§8(로드맵), 역할: [harness/](../harness/README.md).

## 스프린트 인덱스

| 스프린트 | Phase | 목표 | 문서 |
|----------|-------|------|------|
| **Sprint 1** | Phase 1 | 승인/스코프 + Passive 점검 + 최소 레포트 E2E | [sprint-1.md](sprint-1.md) |

## 추정 단위 (Story Point)

피보나치(1·2·3·5·8). 1 SP ≈ 반나절 미만, 5 SP ≈ 1.5~2일, 8 SP ≈ 분할 권장.

## 우선순위 (MoSCoW)

- **Must** — 스프린트 목표 달성에 필수 (빠지면 E2E 불성립)
- **Should** — 중요하나 차순위
- **Could** — 여유 시

## 표준 형식

각 스토리: `ID · 제목 · 사용자 스토리 · 인수조건(AC) · 통제 연계 · SP · 우선순위 · 담당 · 의존성`.
완료 정의는 [PLAN.md](../PLAN.md) §5.3 DoD를 따른다.
