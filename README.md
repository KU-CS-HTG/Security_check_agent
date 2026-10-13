# opsgraph — 공공 IT 운영·보안 지식그래프 + GraphRAG

서버·DB·미들웨어 운영과 정보보안 공개 자료(취약점 정보, 보안 가이드, 점검 항목)를 수집해 지식그래프로 구축하고,
"시스템 구성 → 취약점 → 점검 항목 → 조치 방법 → 근거 지침"을 **근거 경로와 함께** 답하는 GraphRAG를 만든다.
주장: 관계를 따라가야 답이 나오는 질문에서는 벡터 RAG보다 GraphRAG가 낫다(Phase 5에서 정량 평가).

상태: **Phase 0~1 완료, Phase 2 진행 중(2.1 완료, 2.2 문서 조항 분할 구현 완료·실페이지 검증 대기)**.

| 문서 | 내용 |
|---|---|
| [docs/ops/SETUP.md](docs/ops/SETUP.md) | 설치·기동·검증 |
| [docs/sources/SOURCES.md](docs/sources/SOURCES.md) | 데이터 출처 조사표(수집 승인 게이트) |
| [docs/architecture.md](docs/architecture.md) | 아키텍처, 망분리 가정 |
| [docs/security/db-roles.md](docs/security/db-roles.md) | 계정·권한 설계 |
| [docs/adr/](docs/adr/) | 설계 결정 기록 |
| [docs/ops/PHASE1.md](docs/ops/PHASE1.md) | Phase 1 수집기 실행·검증 |
| [docs/ops/PHASE2.md](docs/ops/PHASE2.md) | Phase 2 정규화·추출 (진행 중) |
| [docs/ops/OPERATIONS.md](docs/ops/OPERATIONS.md) | 운영 매뉴얼(뼈대) |

수집 윤리: 승인된 공개 출처만, 공식 API 우선, 호출 간격 제한·캐시·User-Agent 명시, 비밀값은 `.env`(미커밋).
