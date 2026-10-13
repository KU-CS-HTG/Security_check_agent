# 계정·권한 설계서 (초안, Phase 7에서 완성)

## PostgreSQL
원칙: 최소 권한, 용도별 계정 분리, PUBLIC 기본 권한 회수, 비밀값은 `.env`(권한 600).

| 역할 | 용도 | raw | core | DDL | 비고 |
|---|---|---|---|---|---|
| `postgres_admin` | 부트스트랩 전용(확장 설치, 역할 생성) | 전체 | 전체 | 가능 | 앱은 사용하지 않음 |
| `og_owner` | 마이그레이션 | 소유 | 소유 | 가능 | 스키마 소유자 |
| `og_collector` | 수집기 | SELECT, INSERT, UPDATE | 접근 불가 | 불가 | **DELETE 불가**(원본 보존) |
| `og_reader` | 질의 계층 | SELECT | SELECT | 불가 | 읽기 전용 |
| `og_pipeline` | 파싱·추출·검수(Phase 2~) | SELECT | SELECT, INSERT, UPDATE, **DELETE** | 불가 | core는 재생성 가능한 파생 데이터라 DELETE 허용. `core.alembic_version`은 쓰기 불가 |
| `og_airflow` | Airflow 메타데이터 | 접근 불가 | 접근 불가 | 자기 DB만 | 별도 DB `airflow` |

- `REVOKE ALL ON DATABASE ... FROM PUBLIC`, `REVOKE CREATE ON SCHEMA public FROM PUBLIC`.
- 새 테이블 권한은 `ALTER DEFAULT PRIVILEGES FOR ROLE og_owner`로 자동 부여된다 → 마이그레이션은 반드시 `og_owner`로 실행해야 한다.
- 검증: `pytest -m integration`의 권한 매트릭스(허용/거부 19개 케이스, pipeline 포함)로 확인한다.
- 기존 DB에 역할을 추가할 때는 `bash scripts/add_roles.sh`(멱등, 비밀번호 동기화 포함). 마이그레이션은 `core.alembic_version`에서 pipeline의 쓰기 권한을 매번 회수한다.
- 초기화 스크립트(`docker/postgres/init/01-roles.sh`)는 **빈 데이터 볼륨의 첫 기동 때만** 실행된다. 비밀번호를 바꾸려면 `ALTER ROLE`로 변경하거나 볼륨을 재생성한다(절차는 운영 매뉴얼).

## Neo4j Community의 한계 (ADR-0002)
- Community 에디션은 **다중 사용자·역할 기반 접근 제어(RBAC)를 지원하지 않는다**(단일 사용자). 읽기 전용 계정을 DB 수준에서 만들 수 없다.
- 보완책: ① Bolt/HTTP 포트를 loopback에만 바인딩, ② 질의 계층은 `READ_ACCESS` 세션과 파라미터화된 Cypher만 사용(코드 규약, Phase 4에서 테스트), ③ 쓰기는 그래프 적재 모듈만 수행, ④ 비밀번호 `.env` 분리.
- 한계 명시: 앱 계층 우회 시 DB 수준 강제는 없다. Enterprise 또는 대안 DB 도입 시 재검토.

## 비밀값 관리
- `.env`는 git 제외, `chmod 600`, `scripts/preflight.sh`가 권한·기본값(`change-me`) 잔존 여부를 점검한다.
- 로그에 비밀값을 남기지 않는다(`Settings.__repr__` 가림).
