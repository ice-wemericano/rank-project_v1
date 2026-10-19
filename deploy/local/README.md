# 로컬 실측 셋업

단위 테스트가 아니라, **서버를 실제로 띄워 공격을 쏘고 대시보드 숫자가 움직이는 것**을 확인하는 환경.
운영 리소스(NAS MySQL, Redis 6379=angel-journal)와 완전히 분리된다.

## 1. 로컬 MySQL 기동

```bash
cd deploy/local
docker compose up -d          # 최초 기동 시 ../../db/schema.sql 자동 실행(시드 글 3개)
```

## 2. 환경변수 + 서버 실행

```bash
cp deploy/local/env.local.example .env   # 레포 루트에 .env 생성(.gitignore 처리됨)
go run .                                  # http://localhost:9090
```

저장소는 `REDIS_ADDR` 가 없어 **메모리**를 쓴다(운영 Redis 안 건드림). 서버 재시작하면 방어 상태 초기화.

## 3. 대시보드 + 공격

- 대시보드: http://localhost:9090/dashboard.html → 글 레벨을 바꿔가며 관찰
- 게시글(브라우저 정식 흐름): http://localhost:9090/post.html?id=1

### 왜 로컬에선 프록시가 필요 없나

서버가 보는 접속 피어가 loopback(127.0.0.1)이라 `realIP` 가 `X-Forwarded-For` 를 신뢰한다.
그래서 attacker 의 `randomIP()`(XFF)가 **요청마다 다른 '실제 IP'로 먹힌다** → 경로 B(프록시 풀)를
로컬에서 흉내 낼 필요 없이 IP 분산이 재현된다. (`-proxies` 는 원격의 견고한 프록시를 뚫을 때 쓴다.)

### 레벨별 확인 시나리오

```bash
# 대시보드에서 글 1 을 해당 레벨로 설정한 뒤 실행.

# Lv5: 서로 다른 실제 IP 라서 정식 흐름이면 통과(반영률 높음)
go run ./tools/attacker -mode proof -id 1 -n 100 -c 20

# Lv6/Lv8/Lv10: 위와 같이 쏘면 인라인은 통과(반영 ↑) → 15초 안에 스크러버가
#   '여러 IP가 같은 UA/대역/버스트'를 집계로 잡아 소급 차감(대시보드 '소급 차감' 열 −N).

# Lv9: attacker 응답의 reason 이 전부 counted 로 바뀜(불투명 응답, 섀도밴).

# Lv7: attacker(proof)는 디바이스 서명이 없어 no_device 로 막힘.
#   반면 브라우저 post.html 에서는 WebCrypto 서명으로 통과(https/localhost 필요 — localhost 는 OK).
```

## 4. 정리

```bash
cd deploy/local
docker compose down -v        # 로컬 MySQL + 데이터 삭제
```
