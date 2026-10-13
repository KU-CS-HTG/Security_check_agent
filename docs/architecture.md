# 아키텍처

## 데이터 흐름
```mermaid
flowchart LR
  subgraph EXT["외부 네트워크 필요 구간 (수집 단계만)"]
    SRC[승인된 공개 출처<br/>API·문서] --> COL[collectors]
  end
  COL --> RAW[(PostgreSQL raw)]
  subgraph OFFLINE["오프라인(망분리) 동작 구간"]
    RAW --> PARSE[파싱·조항 분할]
    PARSE --> EXTR[엔티티·관계 추출<br/>로컬 LLM + 스키마 검증]
    EXTR --> CORE[(PostgreSQL core)]
    EXTR --> NEO[(Neo4j)]
    PARSE --> EMB[임베딩 - 로컬 모델] --> VEC[(pgvector)]
    NEO --> GQ[GraphRAG]
    VEC --> VQ[Vector RAG]
    GQ --> ANS[답변 + 근거 경로]
    VQ --> ANS
  end
  AF[Airflow] -. 일정 실행 .-> COL
```

## 망분리 가정
- **외부 접속이 필요한 곳은 수집(collectors) 단계뿐**이다. 수집 결과는 PostgreSQL raw 스키마에 저장되며, 이후 파싱·추출·그래프 적재·임베딩·질의는 외부 API 없이 동작해야 한다.
- 임베딩 모델과 LLM은 `config/models.yaml`로 교체한다. 기본은 `provider: local`(GPU: RTX 4070)이고,
  `provider: api`는 `allow_external: true`를 명시해야만 로드된다(코드로 강제, `tests/test_config.py`).
- 실제 망분리 환경에서는 수집 서버와 질의 서버를 분리하고 raw 덤프를 반입하는 방식을 가정한다(Phase 7에서 절차 문서화).

## 서버 환경 전제 (Linux)
- WSL2 Ubuntu + Docker Compose. 저장소는 WSL 파일시스템 안(`~/`)에 둔다.
- 모든 포트는 `127.0.0.1`에만 바인딩한다(외부 노출 없음).
- 컨테이너는 `no-new-privileges`, 재시작 정책 `unless-stopped`, JSON 로그 로테이션(10MB × 5), 메모리 상한을 둔다.
- 데이터는 named volume, 백업 산출물은 `./backups`(git 제외)로 마운트한다.
- 앱 로그는 JSON 한 줄씩 stderr로 출력하고 docker 로그 드라이버가 수집·회전한다.

## 모듈 경계 (도메인 교체 가능성)
| 계층 | 위치 | 교체 시 바꾸는 것 |
|---|---|---|
| 출처 | `config/sources.yaml`, `collectors/` | 수집기와 승인 목록 |
| 스키마 | `migrations/` (raw/core) | 테이블 정의 |
| 온톨로지 | Phase 3에서 `ontology/` | 노드·관계 정의 |
| 모델 | `config/models.yaml` | provider·모델명 |

## 자원 계획 (PC: RAM 32GB, GPU RTX 4070 Laptop VRAM 8GB)
- 시스템 RAM은 넉넉하다. PostgreSQL 1GB + Neo4j 1.5GB + Airflow 2GB 상한을 합쳐도 약 4.5GB이고, WSL 기본 할당(RAM의 50%, 약 16GB)으로 충분하므로 `.wslconfig` 조정은 필수가 아니다.
- 병목은 **GPU VRAM 8GB**다. 로컬 LLM·임베딩 모델 선택에 직접 영향한다(양자화된 7~8B급까지가 현실적, 13B 이상은 CPU 오프로딩 필요). 모델 결정은 Phase 2·4의 ADR에서 한다.
