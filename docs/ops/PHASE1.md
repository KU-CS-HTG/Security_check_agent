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

## 실서버 검증 기록 (2026-10-13, 개발 PC)
| 항목 | 결과 |
|---|---|
| `db upgrade` | 마이그레이션 0001 적용 |
| `osv ecosystems` | 버킷에 46개 생태계, 범위 파일의 `Debian`, `Alpine`, `GIT` 모두 존재. `ecosystems.txt` 재요청은 304로 캐시 재사용 |
| `collect postgresql-security --limit 3` | `inserted 4`(인덱스 1 + CVE 페이지 3), `errors 0`, robots.txt 확인, 요청 간격 약 2초 |
| `collect osv -e Debian --dry-run` | 전체 70,370건 중 범위 해당 284건, 범위 밖 70,086건, Ubuntu 레코드 0건, 라이선스 `UNKNOWN` 284건. all.zip 다운로드 약 2분 10초 |
| `collect osv -e Alpine --dry-run` | 전체 4,729건 중 범위 해당 148건, 라이선스 `UNKNOWN` 148건, `errors 0` |
| `collect osv -e GIT --dry-run` | 전체 113,925건 중 범위 해당 54건(저장소 URL 매칭), 라이선스 `UNKNOWN` 54건, `errors 0` |
| `collect osv -e Debian` 2회 연속 | 두 번째 실행 `inserted 0 / updated 0` (증분 경로와 중복 방지 확인) |

범위 점검: 적재된 레코드의 `affected` 패키지는 `nginx`(226), `postgresql-NN`(7.4~18), `postgresql-common` 등이 대부분이다.
`nghttp2`, `openssl`, `tomcat`, `haproxy` 같은 다른 패키지가 목록에 나오는 것은 오탐이 아니라, 한 레코드(예: HTTP/2 취약점)가
nginx와 함께 여러 제품을 영향 대상으로 나열하기 때문이다. 필터는 "대상 제품이 한 번이라도 나오는 레코드"를 저장하고
레코드는 원문 그대로 보존한다. 제품별 구분은 `matched_products` 컬럼으로 한다.

## 남은 항목과 한계
1. **범위 안의 레코드 486건(Debian 284 + Alpine 148 + GIT 54)이 전부 라이선스 `UNKNOWN`이다.** OSV 문서가 라이선스를 표기한
   업스트림(GHSA, PYSEC 등)에는 대상 제품(PostgreSQL, Nginx)의 레코드가 없었다. Debian 보안 추적기, Alpine secdb, NVD 변환분의
   라이선스를 각각 확인하기 전까지 이 데이터는 **내부 분석·평가 전용**이다(공개 산출물 제외).
2. 같은 취약점이 Debian·Alpine·GIT에 중복으로 나올 수 있다(`export_ecosystem`이 키의 일부). 통합은 Phase 3(그래프)에서 한다.
