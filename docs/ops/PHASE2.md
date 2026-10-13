# Phase 2 (진행 중): 정규화·문서 파싱·추출

| 단계 | 상태 |
|---|---|
| 2.0 결정·역할·설계 | 완료 (ADR-0004~0006, `docs/design/phase2-core-schema.md`) |
| 2.1 OSV·PostgreSQL 공지 정규화(규칙 기반) | PostgreSQL 공지 70건 실데이터로 검증 완료(필드 100%, 점수 불일치 0) |
| **2.2 문서 수집·파싱·조항 분할** | **구현 완료, 실제 페이지 검증 대기** |
| 2.3 LLM 클라이언트(Ollama, Qwen2.5-7B)와 검증·재시도 | 예정 |
| 2.4 추출 실행 | 예정 |
| 2.5 검수 도구와 품질 측정 | 예정 |

## 2.1 무엇을 하나
`raw`(원본 그대로)를 `core`(조회·그래프 적재용 정리본)로 **LLM 없이** 변환한다. 원본은 건드리지 않고, `core`는 언제든 다시 만들 수 있다.

| 원본 | 결과 테이블 |
|---|---|
| `raw.osv_vulnerability` (JSON) | `core.vulnerability`, `core.affected_package`, `core.version_range`, `core.vuln_reference` |
| `raw.web_page` (PostgreSQL 보안 HTML) | `core.pg_advisory` |

- **한 취약점이 여러 생태계에 나와도 `core.vulnerability`는 1행**이다(가장 최근 raw 행 기준, `export_ecosystems`에 모두 기록).
- **버전 범위는 구간으로 풀어 저장**한다. `[introduced 0, fixed 1.2, introduced 2.0, fixed 2.3]`은 2행이다. 닫히지 않은 구간은 `fixed`가 NULL(열린 구간)이다.
- **심각도**: CVSS v3 벡터가 있으면 표준 공식으로 점수를 계산해 구간(LOW/MEDIUM/HIGH/CRITICAL)을 매긴다. 벡터만 있으면(v4, v2) 점수는 NULL, DB가 라벨을 주면 그 라벨(`severity_source`로 출처 구분). **정보가 없으면 NULL**이며 추정하지 않는다.
- **`publishable`**: 라이선스가 `UNKNOWN`이거나 정책상 차단이면 `false`. Debian·Alpine·GIT 변환분은 현재 전부 `false`다.
- **PostgreSQL 공지 파서**는 라벨 기반(`Versions Affected`, `Fixed In`, `Description`, `Component`, CVSS 벡터·점수)이며, 찾지 못한 필드는 NULL로 두고 `parse_flags`에 기록한다. 본문 텍스트는 원문 그대로 보존한다.
- 재실행 안전: raw가 바뀌지 않았으면 건너뛴다(`unchanged`). 바뀐 취약점은 하위 행까지 통째로 재생성한다. 한 레코드가 실패해도 나머지는 계속 진행하고 `errors`와 `notes`에 남긴다.

## 실행 (Git Bash, `.env` 설정 완료 상태)
```bash
git pull origin claude/zealous-bohr-081jz8
pip install -e ".[dev]"                    # beautifulsoup4 추가됨
python -m opsgraph db upgrade              # 마이그레이션 0002 (core 테이블)
python -m opsgraph normalize osv
python -m opsgraph normalize osv           # 재실행: unchanged만 나와야 함
python -m opsgraph normalize pg            # 변환 + 필드별 파싱 성공률 보고
python -m opsgraph inspect-page CVE-2021-23214   # 파서가 한 페이지를 어떻게 읽는지 확인
```
`normalize osv`의 통계는 `processed/inserted/updated/unchanged/errors`이다. 첫 실행의 `processed`는 raw의 **고유 osv_id 수**이고(raw 행 486개 이하), `errors`는 0이어야 한다.

## 검증 SQL (읽기 전용 계정, DBeaver 또는 psql)
```sql
-- 건수와 심각도·공개 가능 여부
SELECT count(*) AS vulns, count(severity_label) AS with_severity,
       count(*) FILTER (WHERE publishable) AS publishable FROM core.vulnerability;
-- 대상 제품의 수정 버전 (배포판별)
SELECT v.osv_id, a.ecosystem, a.package, r.introduced, r.fixed
FROM core.vulnerability v
JOIN core.affected_package a USING (osv_id)
JOIN core.version_range r ON r.affected_id = a.id
WHERE 'postgresql' = ANY (v.matched_products) AND r.fixed IS NOT NULL
ORDER BY v.modified DESC LIMIT 20;
-- PostgreSQL 공지
SELECT cve_id, fixed_versions, cvss_score, parse_flags FROM core.pg_advisory ORDER BY cve_id;
```

## PostgreSQL 공지 파서: 실제 페이지로 확인한 구조 (CVE-2022-1552)
첫 실행에서 필드 성공률이 높아 보였지만(수정 버전 3/3), 실제 페이지 출력을 확인하니 **값이 틀려 있었다**(마지막 행 10.21 누락,
인라인 코드 표기로 문장이 조각남). 아래 구조에 맞춰 파서를 다시 썼다(`PARSER_VERSION = "2"`).

| 페이지 요소 | 처리 |
|---|---|
| `CVE-xxxx-xxxx` 제목 + 바로 뒤의 짧은 제목 | `title = "CVE-…: 짧은 제목"` |
| 라벨 없는 본문 문단(제목~"Version Information" 사이) | `description` (문단 단위, 인라인 `<code>`·`<a>`는 문장에 합침) |
| "Version Information" 표(Affected Version / Fixed In / Fix Published) | `core.pg_advisory_version` 행(메이저 버전 → 수정 마이너 버전, 날짜), `fixed_versions` |
| "CVSS 3.0" 아래 Overall Score / Component / Vector | 점수, 컴포넌트, 벡터(접두사 `CVSS:3.0/`를 붙여 완성). 점수와 벡터 계산값이 다르면 `cvss_score_matches_vector=false` |
| "Reporting Security Vulnerabilities…" | 사이트 안내문이라 본문에서 제외 |

- 파서 규칙을 바꾸면 `PARSER_VERSION`이 오르고, **raw가 그대로여도 저장된 행이 자동으로 다시 만들어진다**(OSV 정규화도 `NORMALIZER_VERSION`으로 같은 방식).
- 테스트 샘플 `PAGE_REAL`은 실제 페이지의 텍스트 출력(문구·순서·값)에 맞춰 만든 것이고 **HTML 태그는 추정**이다. 다른 연도의 페이지가 다른 구조일 수 있어, `normalize pg`의 성공률과 `score_mismatch`를 계속 확인한다.

## 2.2 문서 코퍼스(A): PostgreSQL 공식 문서 → 조항
대상 페이지와 버전은 `config/docs_corpus.yaml`(버전 `18`, 약 25쪽)이다. 라이선스는 PostgreSQL License(공개 가능), 저작권 고지는 문서 행에 함께 저장한다.

```bash
git pull origin claude/zealous-bohr-081jz8
python -m opsgraph db upgrade                          # 0004: core.document, core.clause
python -m opsgraph collect postgresql-docs --dry-run   # 어떤 페이지가 있고 없는지 먼저 확인(DB 쓰기 없음)
python -m opsgraph collect postgresql-docs
python -m opsgraph docs parse                          # 조항으로 분할 + 페이지별 보고
python -m opsgraph docs show auth-pg-hba-conf          # 조항 목록(제목 경로, 크기, 앞부분)
```
- 수집은 robots.txt와 소스 규칙(`docs/<버전>/` 허용, `docs/devel/` 차단)을 지키고, 2초 간격이다. **없는 페이지(404)는 `notes`에 보고되고 건너뛴다**(파일명이 틀린 경우 설정을 고친다).
- 조항 = 소제목 + 다음 소제목 전까지의 본문. 제목 경로(`장 > 절 > 소절`), 출처 URL(`#앵커` 포함), 본문(공백 정규화, `<pre>` 코드와 설정 예시는 줄바꿈 보존)을 저장한다. 6,000자를 넘는 조항은 문단·코드블록 경계에서만 나눈다(`#p1`, `#p2`).
- 목차(`toc`), 이전/다음 링크, 페이지 푸터, 소제목 옆 `#` 링크는 본문에서 제외한다. Note/Warning 같은 박스의 라벨은 섹션이 아니라 본문 줄로 남긴다.
- **조항 ID는 `(문서, 키)`로 식별한다**(키 = 소제목 앵커). 파서 규칙을 바꾸거나 페이지가 갱신돼도 **텍스트가 같은 조항은 같은 ID를 유지**해서, 이후 단계에서 조항에 붙는 추출 결과가 불필요하게 사라지지 않는다. 사라진 소제목의 조항만 삭제된다.

### 2.2 검증 방법과 한계
- 테스트(94개)는 DocBook 출력 구조를 재현한 샘플로 파서를 확인했다. **실제 postgresql.org 페이지는 이 환경에서 볼 수 없으므로** `docs parse`의 페이지별 보고(조항 수, 글자 수, 가장 긴 조항)와 `docs show`로 직접 확인한다.
  - 조항 수가 0인 페이지는 `<-- no clauses`로 표시된다(페이지 구조가 다르다는 신호).
  - 한 조항이 6,000자를 크게 넘거나, 조항이 지나치게 많이 쪼개지면 분할 규칙을 조정한다.
  - `docs show <페이지> --full`로 본문이 원문과 같은지 한두 건 대조한다.

## 알려진 한계
1. **파서는 실제 페이지 1건(CVE-2022-1552)의 출력으로 맞췄다.** 이 환경에서는 postgresql.org에 접속할 수 없다. 다른 연도·형식의 페이지는 `normalize pg`의 필드별 성공률과 `score_mismatch`로 확인하고, 낮은 필드는 `inspect-page` 출력으로 조정한다.
2. Debian·Alpine·GIT 레코드는 CVSS 정보가 없을 수 있어 `severity_label`이 NULL인 비율이 높을 수 있다(정상). 심각도 보강은 이후 PostgreSQL 공지의 CVSS와 연결해서 한다.
3. 같은 취약점의 배포판별 항목 통합(Debian의 DSA와 Alpine의 CVE 등)은 Phase 3(그래프)에서 `aliases`로 연결한다.
