# Phase 2 (진행 중): 정규화·문서 파싱·추출

| 단계 | 상태 |
|---|---|
| 2.0 결정·역할·설계 | 완료 (ADR-0004~0006, `docs/design/phase2-core-schema.md`) |
| **2.1 OSV·PostgreSQL 공지 정규화(규칙 기반)** | **구현 완료, 실데이터 검증 대기** |
| 2.2 문서 수집·파싱·조항 분할 | 예정 |
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

## 알려진 한계
1. **PostgreSQL 공지 파서는 실제 페이지로 검증되지 않았다.** 이 환경에서 postgresql.org에 접속할 수 없어, 테스트는 예상한 페이지 형태를 흉내 낸 샘플(3종)로만 했다. `normalize pg`의 **필드별 성공률**이 실제 상태를 보여 준다. 낮은 필드가 있으면 `inspect-page`의 출력(페이지 텍스트 앞 60줄)을 보내 주면 파서를 맞춘다.
2. Debian·Alpine·GIT 레코드는 CVSS 정보가 없을 수 있어 `severity_label`이 NULL인 비율이 높을 수 있다(정상). 심각도 보강은 이후 PostgreSQL 공지의 CVSS와 연결해서 한다.
3. 같은 취약점의 배포판별 항목 통합(Debian의 DSA와 Alpine의 CVE 등)은 Phase 3(그래프)에서 `aliases`로 연결한다.
