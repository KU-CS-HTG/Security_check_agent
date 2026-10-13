# Phase 2 설계: `core` 스키마 (계획, 단계별로 마이그레이션 추가)

원칙: `raw`는 원본 그대로(수정 금지), `core`는 raw에서 **재생성 가능한 파생 데이터**. 모든 행에 `source_url`, `license`,
원본 참조(raw의 키)를 둔다. 라이선스가 `UNKNOWN`이거나 KOGL 제3·4유형이면 `publishable=false`.

## 2.1 정규화 (규칙 기반)
| 테이블 | 주요 컬럼 |
|---|---|
| `core.vulnerability` | `osv_id` PK, `aliases text[]`(CVE 등), `summary`, `details`, `severity_vector`, `severity_score`, `severity_label`, `published`, `modified`, `withdrawn`, `license`, `source_url`, `publishable` |
| `core.affected_package` | `id`, `osv_id` FK, `ecosystem`, `package`, `purl` |
| `core.version_range` | `id`, `affected_id` FK, `range_type`, `introduced`, `fixed`, `last_affected` |
| `core.vuln_reference` | `osv_id` FK, `ref_type`, `url` |
| `core.pg_advisory` | `cve_id` PK, `title`, `description`(원문), `cvss_score`, `cvss_vector`, `affected_versions`, `fixed_versions text[]`, `source_url`, `license` |

- 한 취약점이 여러 export 생태계에 나올 수 있으므로 `osv_id` 기준으로 합치고 출처 행은 raw 참조로 남긴다.
- `severity_label`은 CVSS 점수의 표준 구간(Low/Medium/High/Critical)에서 규칙으로 산출한다.

## 2.2 문서와 조항
| 테이블 | 주요 컬럼 |
|---|---|
| `core.document` | `id`, `source_id`, `title`, `url`, `version`, `license`, `kogl_type`, `format`, `content_hash`, `fetched_at`, `publishable` |
| `core.clause` | `id`, `document_id` FK, `ordinal`, `heading_path text[]`, `text`(원문 그대로), `text_hash`, `source_url`(앵커 포함) |

## 2.3~2.4 추출
| 테이블 | 주요 컬럼 |
|---|---|
| `core.extraction_run` | `id`, `model`, `prompt_version`, `schema_version`, `params jsonb`, `started_at`, `finished_at` |
| `core.extracted_item` | `id`, `run_id` FK, `clause_id` FK, `entity_type`(check_item / remediation / category), `payload jsonb`, `evidence_quote`, `evidence_verified bool`, `attempts int`, `status`(pending/approved/rejected), `risk_source`, `review_note`, `reviewed_at` |

## 2.5 검수
검수 화면이 `status`와 `review_note`를 갱신한다(`og_pipeline` 역할). 승인된 항목만 Phase 3의 그래프 적재 대상이다.

## 권한
`og_pipeline`: raw SELECT, core SELECT/INSERT/UPDATE/DELETE(`alembic_version` 제외). 수집은 `og_collector`(raw 쓰기)만 한다.
