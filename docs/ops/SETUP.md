# 설치·기동 (Phase 0)

전제: Windows 11 + WSL2(Ubuntu) + Docker Desktop(WSL 통합 켜기), Git. (PC: RAM 32GB, GPU VRAM 8GB 기준)
WSL이 없으면 PowerShell에서 `wsl --install -d Ubuntu`. 저장소는 Ubuntu 홈(`~/`) 아래에 둔다. Git Bash에서도 동작은 하지만 파일 권한(chmod 600)이 강제되지 않아 preflight가 경고한다.
포트가 이미 사용 중이면 `.env`의 `POSTGRES_PORT`, `NEO4J_HTTP_PORT`, `NEO4J_BOLT_PORT`, `AIRFLOW_PORT`를 바꾼다(`NEO4J_URI`의 포트도 함께).

## 1. 코드와 Python 환경 (WSL Ubuntu 터미널)
```bash
cd ~ && git clone <저장소 URL> opsgraph && cd opsgraph
git checkout claude/zealous-bohr-081jz8
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## 2. 비밀값
```bash
cp .env.example .env && chmod 600 .env
# 모든 change-me를 서로 다른 강한 값으로 교체. HTTP_CONTACT에는 본인 이메일.
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # AIRFLOW_FERNET_KEY (cryptography 필요: pip install cryptography)
```

## 3. 사전 점검과 기동
```bash
bash scripts/preflight.sh
docker compose up -d --wait postgres neo4j
docker compose --profile airflow up -d --build --wait     # Airflow(선택)
```

## 4. 검증
```bash
pytest                         # 단위 테스트
pytest -m integration          # DB 권한 매트릭스 (DB가 떠 있어야 함. .env를 자동 로드)
set -a; . ./.env; set +a
docker compose exec postgres psql -U "$POSTGRES_SUPERUSER" -d "$POSTGRES_DB" -c "SELECT extname FROM pg_extension;"   # vector
docker compose exec postgres psql -U "$POSTGRES_SUPERUSER" -d "$POSTGRES_DB" -c "\du"                             # 4개 역할
docker compose ps                                                                                                  # healthy 확인
```
Neo4j 브라우저: http://localhost:7474 (loopback 전용). 초기화 스크립트를 다시 실행하려면 `docker compose down -v`(데이터 삭제).

## 5. 출처 조사 (승인 게이트)
`docs/sources/SOURCES.md`의 절차대로 `python scripts/probe_sources.py --contact 이메일`을 실행한다.
