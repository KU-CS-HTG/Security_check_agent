# 운영 매뉴얼 (뼈대, Phase 7에서 완성)

단계마다 운영 메모를 이 문서에 누적한다. 아래 항목은 Phase 7까지 채워야 할 목차다.

1. 기동·중지 절차 (Phase 0 내용은 SETUP.md 참고)
2. 일상 점검 항목 (컨테이너 상태, 디스크, 로그, 수집 성공 여부)
3. 로그 관리 (JSON 로그 위치, docker 로테이션 10MB×5, 보관 기간)
4. 백업·복구 (PostgreSQL `pg_dump`, Neo4j 중지-덤프, **복구 테스트 기록**)
5. 계정·권한 변경 절차 (`docs/security/db-roles.md` 연계)
6. 장애 대응: 수집 실패, DB 기동 실패, 디스크 부족, Airflow 스케줄러 중단
7. 변경 이력 (출처 승인, 스키마 마이그레이션, 비밀번호 교체)

## 메모 (Phase 0)
- Postgres 초기화 스크립트는 빈 볼륨 첫 기동 때만 실행된다.
- 모든 서비스 포트는 127.0.0.1 바인딩.

## 메모 (Phase 1)
- 수집은 collector 역할(INSERT/UPDATE만)로 실행하고, 마이그레이션만 owner 역할로 실행한다(`python -m opsgraph db upgrade`).
- 수집 실패 확인: `SELECT * FROM raw.collection_run ORDER BY id DESC;` (`status`: ok / partial / failed).
- 중복 방지는 `content_hash` 비교다. 캐시(`data/http_cache`)와 다운로드(`data/osv`)는 지워도 안전하다(다시 받을 뿐).
- 수집기 통합 테스트는 테이블을 TRUNCATE하므로 `OPSGRAPH_ALLOW_TRUNCATE=1`을 줄 때만 실행되고, 실데이터가 있는 DB에서는 실행하지 않는다.

## 메모 (Phase 2.1)
- 정규화는 `og_pipeline` 역할로 실행한다(raw 읽기, core 쓰기). `core`는 raw에서 언제든 재생성 가능하다: `python -m opsgraph normalize osv --force`.
- 정규화 이상 징후: `normalize pg`의 파싱 성공률이 낮으면 `inspect-page <CVE>`로 페이지 구조를 확인한다.
