# Phase 1: 수집기와 raw 적재 (실행·검증 가이드)

## 구성
| 구성요소 | 위치 | 역할 |
|---|---|---|
| HTTP 클라이언트 | `src/opsgraph/http.py` | User-Agent(연락처 필수), 호스트별 간격, robots.txt, 재시도/Retry-After, ETag 캐시, 스트리밍 다운로드 |
| 범위 정의 | `config/osv_scope.yaml`, `src/opsgraph/scope.py` | (b) 대상 제품(PostgreSQL, Nginx)에 해당하는 OSV 레코드만 선별 |
| 라이선스 | `src/opsgraph/licensing.py` | OSV id 접두사 → 라이선스. Ubuntu(CC-BY-SA)는 제외 |
| OSV 수집기 | `collectors/osv.py` | 최초: `<ECO>/all.zip`, 이후: `modified_id.csv` 증분 |
| PostgreSQL 수집기 | `collectors/postgresql_security.py` | 보안 인덱스와 CVE 페이지 원문 HTML |
| 스키마 | `migrations/versions/0001_raw_schema.py` | `raw.*` 테이블, 마이그레이션은 owner 역할로 실행 |
| 저장 | `storage/repository.py` | collector 역할로 INSERT/UPDATE만, 해시로 중복 방지 |

## raw 테이블
- `raw.osv_vulnerability` (PK `osv_id, export_ecosystem`): `payload`(JSONB 원문), `content_hash`, `source_url`, `fetch_url`, `license`, `matched_products`, `modified`, `collected_at`
- `raw.web_page` (PK `url`): `body`(HTML 원문), `content_hash`, `source_url`, `license`, `collected_at`(내용이 바뀐 시각)
- `raw.collection_state`: ecosystem별 증분 기준(커서). `raw.collection_run`: 실행 이력(상태, 통계, 오류)

## 증분과 중복 방지
- 자연키 기준 upsert, `content_hash`가 같으면 변경 없음으로 처리한다(재실행해도 행이 늘지 않음).
- OSV 커서는 **오류 없이 끝까지** 처리했을 때만 전진한다. `--limit` 중단이나 오류가 있으면 전진하지 않아 다음 실행이 이어서 처리한다.
- 라이선스 정책: `UBUNTU-*`/`USN-*`와 Ubuntu 패키지가 있는 레코드는 저장하지 않는다(ADR-0003). DSA/DLA, Alpine, NVD 변환분은 OSV 문서에 라이선스 표기가 없어 `UNKNOWN`으로 저장하고 통계(`unknown_license`)에 센다. 공개 산출물에는 `UNKNOWN`을 쓰지 않는다.

## 실행 (PC, `.env`의 `HTTP_CONTACT` 필수)
```bash
python -m opsgraph db upgrade                           # 스키마 생성 (owner 역할)
python -m opsgraph osv ecosystems                       # 범위 파일의 생태계가 실제로 있는지 확인
python -m opsgraph collect postgresql-security --limit 3 --dry-run
python -m opsgraph collect postgresql-security --limit 3
python -m opsgraph collect osv -e Debian --dry-run      # all.zip을 받아 필터만 수행, DB 쓰기 없음
python -m opsgraph collect osv -e Debian                # 실제 적재
python -m opsgraph collect osv -e Debian                # 재실행: inserted 0이어야 함
```
출력은 통계 JSON(`inserted/updated/unchanged/skipped_scope/skipped_license/unknown_license/errors/notes`).
`errors`가 있으면 종료 코드 1.

## 검증 SQL (읽기 전용 역할)
```sql
SELECT export_ecosystem, count(*), count(*) FILTER (WHERE license='UNKNOWN') AS unknown
FROM raw.osv_vulnerability GROUP BY 1;
SELECT osv_id, matched_products, license FROM raw.osv_vulnerability ORDER BY modified DESC LIMIT 10;
SELECT source_id, status, started_at, stats FROM raw.collection_run ORDER BY id DESC LIMIT 5;
SELECT count(*), count(DISTINCT url) FROM raw.web_page;   -- 두 값이 같아야 함 (중복 없음)
```

## 테스트
```bash
pytest                       # 단위 + (DB가 있으면) 통합. 네트워크 불필요, HTTP는 모킹
pytest -m integration        # DB 필요: docker compose up 후 python -m opsgraph db upgrade
```
통합 테스트는 `TRUNCATE`를 쓰므로 **개발 DB에서만** 실행한다(실데이터가 있으면 지워진다).

## 이 환경에서 검증하지 못한 가정 (PC에서 스모크 테스트 필요)
클라우드 환경이 OSV·GCS·postgresql.org에 접속할 수 없어, 아래는 문서와 기억에 기반한 가정이다.
1. 버킷 URL 구조: `https://storage.googleapis.com/osv-vulnerabilities/<ECO>/{all.zip,modified_id.csv,<ID>.json}`와 `ecosystems.txt`
2. `modified_id.csv` 형식 `"<iso>,<id>"`(OSV 데이터 페이지에 기재된 형식을 따름)
3. 생태계 이름 `Debian`, `Alpine`, `GIT` 존재 여부 → `osv ecosystems`로 확인, 없으면 보고만 하고 건너뜀
4. PostgreSQL 보안 인덱스가 `/support/security/CVE-YYYY-NNNN/` 링크를 갖는 구조 → 링크를 못 찾으면 `errors`와 노트로 알림
5. `GIT` 생태계의 크기: 크면 `config/osv_scope.yaml`에서 빼거나 `max_download_mb`를 조정한다.
