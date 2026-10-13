# Phase 2 (진행 중): 정규화·문서 파싱·추출

| 단계 | 상태 |
|---|---|
| 2.0 결정·역할·설계 | 완료 (ADR-0004~0006, `docs/design/phase2-core-schema.md`) |
| 2.1 OSV·PostgreSQL 공지 정규화(규칙 기반) | PostgreSQL 공지 70건 실데이터로 검증 완료(필드 100%, 점수 불일치 0) |
| 2.2 문서 수집·파싱·조항 분할 | 24쪽 → 216조항 실데이터로 검증 완료 |
| **2.3 LLM 클라이언트·구조화 출력·근거 검증·재시도** | **구현 완료, 실제 모델 시험 대기** |
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

### 2.2 실제 페이지 첫 결과(24쪽, 오류 0)와 파서 개선 (`PARSER_VERSION = "2"`)
첫 실행에서 24쪽이 모두 처리됐지만 조항 분할이 거칠었다. 예: `runtime-config-logging` 10조항/39,759자, `runtime-config-connection`
6조항/23,721자, `auth-pg-hba-conf` 5조항/24,518자(최대 6,043자)처럼 **설정 항목 수십 개가 글자 수 기준으로 잘려** 6,000자 덩어리가 됐다.

- **용어 단위 분할**: 3,500자를 넘는 절에 용어 목록(`dt`/`dd`)이 둘 이상이면 **용어 하나를 조항 하나**로 만든다(설명과 용어를 떼어 놓지 않음).
  조항의 제목 경로 끝에 용어(`log_connections (boolean)`)가 붙고, 용어 요소의 `id`가 있으면 그것이 키와 출처 URL 앵커가 되어
  인용이 `…#GUC-LOG-CONNECTIONS`처럼 설정 단위로 정확해진다(없으면 용어 텍스트로 키를 만든다). 소개 문단은 별도 조항이다.
- **공백 버그 수정**: 인라인 코드 뒤에 구두점이 오면 `trust ,`처럼 공백이 끼던 문제를 고쳤다. 다음 단계의 "원문 근거 문장 검증"은 인용문이
  원문 텍스트의 부분 문자열인지 보므로, 텍스트가 원문과 같아야 한다.
- 대상에 `predefined-roles` 추가(`default-roles`는 PostgreSQL 14 이후 안내 페이지로 보이며 379자뿐이었다).
- 파서 버전이 올라서 **저장된 문서가 자동으로 다시 만들어진다**(조항 키가 바뀌어 이전 조항은 삭제되고 새로 생성된다. 아직 추출 결과가 없어 영향 없음).

### 2.2 확인 방법
```bash
git pull origin claude/zealous-bohr-081jz8
python -m opsgraph collect postgresql-docs     # predefined-roles 추가분 수집
python -m opsgraph docs parse                  # 페이지별 조항 수·글자 수·최장 조항
python -m opsgraph docs show runtime-config-logging
python -m opsgraph docs show runtime-config-logging --full   # 본문을 사이트 원문과 대조
```
- `runtime-config-logging`, `runtime-config-connection`은 **수십 개 조항**(설정 하나당 하나)이 되어야 하고, 최장 조항이 6,000자보다 훨씬 짧아져야 한다.
- 조항 목록에서 `log_connections (boolean)` 같은 제목 경로와 `#GUC-…` 앵커가 보이는지 확인한다.
- 한계: 용어 목록이 아닌 긴 산문 절(예: `continuous-archiving`)은 여전히 문단 경계에서 크기 기준으로 나뉜다.

### 2.2 실제 결과 (24쪽 → 217조항, 오류 0)와 파서 v3
`docs parse`(v2)의 결과: `runtime-config-logging` 44조항(설정 하나당 하나), `runtime-config-connection` 39조항, `auth-pg-hba-conf` 32조항,
`ddl-priv` 16조항, 최장 조항 5,808자. 조항의 출처 URL이 `…#GUC-LOG-CONNECTIONS`처럼 설정 단위 앵커를 가진다(용어 요소의 `id` 사용).

v3 변경:
- 용어(`dt`)가 연속되고 설명(`dd`)이 하나인 경우 하나의 조항으로 묶는다(설명 없는 조항 방지).
- `docs parse`는 코퍼스 설정(`docs_corpus.yaml`)에 더 이상 없는 문서를 `core`에서 제거한다(raw는 건드리지 않음). `default-roles`(373자, 안내 페이지)를 코퍼스에서 뺐다.

미해결(확인 중): 일부 문장에서 단어가 붙어 보인다(`determinesthe`, `thesame`, `Thisparameter`, `Section 27.1for`).
정상 공백(줄바꿈, CRLF, NBSP, 인라인 뒤 줄바꿈)은 파서가 공백 하나로 바꾸는 것을 테스트로 확인했다.
따라서 원문에 **보이지 않는 문자(제로폭 공백, 소프트 하이픈 등)**가 있는지 실제 바이트를 확인해야 한다:
```sql
SELECT encode(convert_to(substr(text, position('determines' in text) + 8, 8), 'UTF8'), 'hex') AS hex,
       substr(text, position('determines' in text), 22) AS snippet
FROM core.clause WHERE key = 'GUC-LOG-ROTATION-SIZE';
```
(`20`이면 정상 공백, `e2808b`는 제로폭 공백, `c2ad`는 소프트 하이픈.)

## 2.3 LLM 추출 (조항 → 점검 항목 후보)

```
조항 텍스트 ──프롬프트(규칙 8개 + 예시 1개)──> 로컬 LLM(Ollama, JSON 스키마 강제, temperature 0)
   └─ 응답 ─ JSON 파싱 ─ pydantic 검증 ─ 인용문이 조항 원문에 있는지 검증 ─┬ 통과 → 저장(pending)
                                                                          └ 실패 → 문제를 알려 주고 재시도(최대 3회)
```

**추출 항목(`CheckItemDraft`)**: `title`, `category`(11개 고정 목록), `target`(설정·파일·객체), `check_method`, `recommended_value`,
`remediation`, `risk_level`(high/medium/low/not_stated), `evidence_quote`(원문 그대로 1~2문장), `remediation_quote`.
스키마는 평평하게 직접 작성했다(`$ref`·null 유니온 없음, 빈 문자열과 `not_stated`가 "없음"). 로컬 런타임의 제약 디코딩이 JSON Schema 일부만 지원하기 때문이다.

**환각 방지(핵심)**
- 모든 항목은 `evidence_quote`가 **조항 원문에 실제로 있어야** 통과한다. 비교는 공백·줄바꿈, 눈에 보이지 않는 문자(제로폭 공백, 소프트 하이픈),
  타이포그래피 따옴표·대시 차이를 무시한다(`exact`). 단어가 붙어 있는 경우를 위해 공백을 모두 무시한 `loose` 수준도 있다.
  20자 미만·600자 초과 인용은 근거로 인정하지 않고, `...`로 생략한 인용은 각 조각이 순서대로 있어야 한다.
- `remediation_quote`가 있으면 그것도 검증한다. `target`이 조항이나 제목 경로에 없으면 `target_found=false`로 표시한다(차단하지 않고 검수 신호로 사용).
- 위험도는 **문서가 말한 경우에만** 채운다(프롬프트 규칙 5). 문서가 말한 값이면 `risk_source=document`, 아니면 비워 둔다.
- 검증 실패나 스키마 위반은 **무엇이 틀렸는지 모델에게 알려 주고 다시 요청**한다(최대 `max_attempts`, 기본 3). 끝내 검증되지 않은 항목은
  `status=rejected`(자동 반려, 사유 기록)로 **저장은 하되 사용하지 않는다**. 그래야 환각률을 나중에 계산할 수 있다.

**저장(`core.extraction_*`, 마이그레이션 0005)**: 실행 이력(`extraction_run`), 조항별 결과(`extraction_result`: 상태 ok/empty/failed, 시도 횟수,
토큰, 소요 시간, 마지막 원본 응답), 항목(`extracted_item`: pending/approved/rejected, 검증 여부, 일치 수준, 검수 메모).
- **이어하기**: 조항마다 바로 커밋하므로 중단(Ctrl+C)해도 잃는 것이 없고, 다시 실행하면 끝난 조항은 건너뛴다.
  결과 키는 `(조항 텍스트 해시, 모델, 프롬프트 버전)`이라서 **조항이 바뀌거나 모델·프롬프트가 바뀌면 자동으로 다시 한다**. 실패한 조항은 다음 실행에서 다시 시도한다.
- 망분리: LLM 주소는 루프백·사설 주소만 허용한다(`allow_external: true`가 아니면 거부).

### 실행 (Git Bash)
```bash
git pull origin claude/zealous-bohr-081jz8
python -m opsgraph db upgrade                 # 0005
python -m opsgraph llm check                  # 모델 연결, 스키마 준수, 속도(tok/s) 확인
python -m opsgraph extract run --page auth-pg-hba-conf --limit 10   # 10개 조항 시험
python -m opsgraph extract show auth-pg-hba-conf                     # 조항별 결과와 인용문
python -m opsgraph extract stats                                     # 품질 숫자
```
- `extract show --problems`: 실패했거나 근거가 검증되지 않은 것만 본다.
- 첫 호출은 모델을 GPU에 올리느라 10~30초 걸릴 수 있다. 응답이 400이면 Ollama가 오래되어 JSON 스키마 `format`을 지원하지 않는 것이니 최신으로 업데이트한다.

### 첫 실제 시험 결과 (Qwen2.5-7B-Instruct, `auth-pg-hba-conf` 10조항, 프롬프트 v1)
- 처리량: 10조항 56초(평균 5.6초, 최대 11.6초), 프롬프트 1,187 토큰/조항, 실패 0, 재시도 2건. **217조항 전체 약 20분.**
- 근거 인용 검증: 항목 12개 중 11개 통과(91.7%).
- **발견한 문제와 조치(프롬프트 v2, 스키마 v2)**

| 문제 | 조치 |
|---|---|
| 문서에 없는 위험도(`medium`)를 모델이 추정, 그대로 두면 `risk_source=document`로 잘못 기록됨 | `risk_quote` 필드 추가. **위험도는 그 인용이 원문에서 검증될 때만 인정**하고, 아니면 `not_stated`로 내려 `risk_level_claimed`에 기록 |
| `The default behavior…`가 원문의 `…since the default behavior…`와 첫 글자 대소문자만 달라 3회 시도 모두 반려 | 인용 비교에서 **대소문자 무시** |
| "pg_hba.conf file is correctly configured", 조치 "Ensure … correctly specified" 같은 공허한 항목, 문법만 설명하는 조항(`database`, `user`, `address`)에서 항목 생성 | 프롬프트 규칙 추가: 문법·형식 설명은 빈 결과, 제목은 구체적 조건(`correctly` 등 금지), 조치는 제목의 반복 금지, 예시 2개(항목 있음/없음) |
| `target`을 모델이 지어냄(원문에 없음, 3건) | `target`은 원문의 식별자 하나를 그대로 복사 (검증은 계속 비차단 신호) |

- **글자 붙음**(`determinesthe`, `moreinformation`, `risk=mediumverified`)은 데이터 문제가 아니라 **터미널 자동 줄바꿈 위치에서 복사할 때 줄 끝 공백이 빠지는 현상**일 가능성이 크다(코드가 공백 두 칸을 넣는 `risk=… {mark}`에서도 같은 현상이 보였다).
- 한계(규칙으로 해결 불가): 인용이 원문에 **있어도** 항목을 뒷받침하지 않을 수 있다(예: 인용은 `pg_hba_file_rules` 뷰를 설명하는데 제목은 "monitored for changes"). 이는 사람 검수(2.5)로 걸러내고 승인율로 측정한다.

### 이 환경에서 검증한 것과 못 한 것
- 검증: 재시도·피드백, 인용 검증, 이어하기, 오래된 결과 처리, 역할 권한을 **스크립트로 재생한 가짜 모델**로 테스트했다(143개). 변이 테스트로
  "모든 항목을 검증됨 처리", "재시도 제거", "이어하기 무시"를 각각 테스트가 잡는 것을 확인했다. 가짜 Ollama HTTP 서버로 CLI(`llm check`, `extract run/show/stats`)도 끝까지 확인했다.
- **못 한 것**: 실제 Qwen2.5-7B의 출력 품질, 속도, JSON 스키마 강제가 실제 Ollama 버전에서 받아들여지는지. 위 `llm check`와 시험 실행으로 확인한다.

## 알려진 한계
1. **파서는 실제 페이지 1건(CVE-2022-1552)의 출력으로 맞췄다.** 이 환경에서는 postgresql.org에 접속할 수 없다. 다른 연도·형식의 페이지는 `normalize pg`의 필드별 성공률과 `score_mismatch`로 확인하고, 낮은 필드는 `inspect-page` 출력으로 조정한다.
2. Debian·Alpine·GIT 레코드는 CVSS 정보가 없을 수 있어 `severity_label`이 NULL인 비율이 높을 수 있다(정상). 심각도 보강은 이후 PostgreSQL 공지의 CVSS와 연결해서 한다.
3. 같은 취약점의 배포판별 항목 통합(Debian의 DSA와 Alpine의 CVE 등)은 Phase 3(그래프)에서 `aliases`로 연결한다.
