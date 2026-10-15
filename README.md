# suricontroller

Suricata를 여러 노드(OpenWRT 라우터, 서버, 엔드포인트)에 배포하고 중앙에서 관리하는 솔루션입니다.

| 컴포넌트 | 설명 |
|---|---|
| **suri-controller** | 중앙 컨트롤러. 다른 Go 프로그램에 라이브러리로 embed할 수 있습니다(`controller` 패키지). |
| **suri-controller-web** | 웹 관리 UI. 컨트롤러 바이너리에 내장됩니다(`web` 패키지). |
| **suri-node-agent** | 노드 에이전트. Suricata(8.0.5 이상)와 함께 Docker로 설치합니다. |

주요 기능은 다음과 같습니다.

- **E2E 암호화 통신**: `WebSocket → Noise_IK → yamux → protobuf` 구조라서 cloudflared나 리버스 프록시가 TLS를 종단해도 종단 간 암호화가 유지됩니다. 키는 `ssh-ed25519` 형식을 씁니다.
- **인터페이스별 모드**: Off / IDS(af-packet) / IPS(NFQUEUE)를 정합니다. 관리 대상 인터페이스와 IPS 허용 여부는 에이전트 쪽에서 결정합니다.
- **룰/설정의 git 관리**: go-git을 씁니다.
  - ET Open을 주기적으로 받아오고, local 룰은 UI에서 편집합니다.
  - disable/enable/drop/modify는 suricata-update와 같은 결과를 내도록 Go로 포팅했습니다(golden test로 검증).
  - 배포 정책은 auto(최신 커밋 추적), pinned(특정 commit 고정·롤백), paused(배포 중지) 중에서 고릅니다.
- **노드별 버전 관리와 검증**: 노드는 받은 설정을 `suricata -T`로 검증한 뒤 적용합니다. 실패하면 롤백하고 원인을 보고합니다. 룰만 바뀐 경우에는 재시작 없이 reload합니다.
- **로그 수집**: 전역 또는 노드별로 고를 수 있습니다.
  - 로그 파일 위치는 노드 사용자가 정합니다. 그래서 Elastic Agent 같은 외부 수집기와 함께 쓸 수 있습니다.
  - 에이전트와 컨트롤러 모두 메모리 큐를 씁니다. 큐가 가득 차면 오래된 것부터 버립니다.
  - 컨트롤러는 노드별 파일로 저장하고 rotation/retention 정책을 적용합니다.

설계는 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)를 참고하세요.

### suritap: TLS 종단 프록시 평문 검사

TLS를 종단하는 프록시(Traefik, Kong 등)가 복호화한 평문을 공유메모리(또는 UNIX 소켓)로 Suricata에 넘기고, 요청 단위 판정(pass/drop)을 받습니다.

- `tap/suritap-plugin`: Rust로 작성한 Suricata capture plugin
- `pkg/suritap`: Go 클라이언트
- `tap/suritap`: Rust 클라이언트 (crates.io [`suritap`](https://crates.io/crates/suritap), `v*` 태그 때 CI가 게시)
- `adapters/traefik-plugin`: Traefik 플러그인(Yaegi). 공식 Traefik에 그대로 로드되며 소켓 전송을 씁니다. 라우터별 미들웨어로 설정합니다. 별도 저장소 [jc-lab/suritap-traefik](https://github.com/jc-lab/suritap-traefik)의 submodule이므로 `git clone --recursive`(또는 `git submodule update --init`)로 받습니다.
- `adapters/traefik` + `deploy/traefik`: 패치 빌드용 어댑터와 Traefik 패치(`make traefik`). 공유메모리를 쓰고 TLS 종단 TCP 라우터도 검사합니다(`entryPoints.<name>.suritap`).
- `adapters/kong`: Kong 플러그인(Lua, `suritap`과 응답 prevent용 `suritap-response`). 소켓 전송을 cosocket으로 씁니다.
- controller 통합: agent의 `tap` 인스턴스(`agent.yaml`의 `tap:`)와 엔드포인트별 Off/Detect/Prevent. 웹 UI의 노드 › Proxy endpoints에서 정하면, Suricata를 재시작하지 않고 프록시에 몇 초 안에 반영됩니다.

명세와 검증 결과는 [docs/suritap.md](docs/suritap.md)를 참고하세요.

## 빠른 시작

### 1. 컨트롤러

```sh
# 바이너리
make web build
SURICONTROLLER_DATA_DIR=./data SURICONTROLLER_ADMIN_PASSWORD='change-me' ./bin/suri-controller serve

# Docker
docker build -f deploy/controller/Dockerfile -t suri-controller .
docker run -d -p 127.0.0.1:8080:8080 -v $PWD/data:/var/lib/suricontroller \
  -e SURICONTROLLER_ADMIN_PASSWORD='change-me' suri-controller
```

- 웹 UI: `http://localhost:8080/`
- 에이전트 엔드포인트: `/agent/v1/connect`
- HTTPS는 리버스 프록시나 cloudflared tunnel에서 처리하는 것을 권장합니다. 직접 처리하려면 `tls.cert_file`/`tls.key_file`을 지정합니다. 평문 HTTP로만 접속한다면 `SURICONTROLLER_INSECURE_COOKIE=1`을 설정합니다.

주요 설정은 다음과 같습니다. 설정 파일은 `-config`로, 환경 변수는 `SURICONTROLLER_*`로 줍니다.

| 설정 | 환경 변수 | 기본값 |
|---|---|---|
| `listen` | `SURICONTROLLER_LISTEN` | `:8080` |
| `data_dir` | `SURICONTROLLER_DATA_DIR` | `/var/lib/suricontroller` |
| `admin.username` | `SURICONTROLLER_ADMIN_USERNAME` | `admin` |
| `admin.password` / `admin.password_hash` | `SURICONTROLLER_ADMIN_PASSWORD(_HASH)` | (필수) |
| `insecure_cookie` | `SURICONTROLLER_INSECURE_COOKIE` | `false` |
| `trust_proxy_headers` | `SURICONTROLLER_TRUST_PROXY_HEADERS` | `false` |
| `et_open` | `SURICONTROLLER_ET_OPEN` | `true` (첫 실행 시 ET Open 활성화) |

`suri-controller hostkey`를 실행하면 에이전트에 넣을 컨트롤러 공개키가 출력됩니다. `suri-controller hash-password`는 비밀번호의 bcrypt 해시를 만듭니다.

### 2. 노드 에이전트

```sh
docker build -f deploy/agent/Dockerfile -t suri-node-agent .
mkdir -p etc && cp deploy/agent/agent.yaml.example etc/agent.yaml   # node_id, controller.url, host_key, interfaces 수정
docker run --rm -v $PWD/etc:/etc/suri-agent suri-node-agent keygen -node-id router-01
# 출력된 "ssh-ed25519 AAAA... router-01" 라인을 웹 UI의 Nodes > Add node에 등록합니다.
docker compose -f deploy/agent/docker-compose.yml up -d
```

- 컨테이너는 `network_mode: host`와 `NET_ADMIN`/`NET_RAW` 권한으로 실행됩니다. 호스트 파일시스템은 `/host`에 마운트되고, nft/iptables/uci 같은 호스트 도구는 chroot로 실행됩니다.
- `/etc/suricata/suricata.yaml`은 사용자 소유입니다. 컨트롤러가 관리하는 키를 제외하면 자유롭게 고칠 수 있습니다. 컨트롤러 설정에 덮여 적용되지 않는 키는 UI에 경고로 표시됩니다.
- 등록되지 않은 키로 접속하면 거부됩니다.
- `suri-node-agent check`는 설정, 호스트, Suricata, 방화벽, 컨트롤러 연결을 점검합니다.

> OpenWRT의 flow offloading이 켜져 있으면 해당 트래픽은 Suricata를 우회합니다. 이 경우 에이전트가 경고를 보고합니다.

### 3. 다른 프로그램에 embed

```go
admin, _ := auth.NewStaticAdmin("admin", password)
sessions, _ := auth.NewCookieSession(auth.CookieSessionConfig{Login: admin, Secret: secret})
ctl, err := controller.New(controller.Options{DataDir: dir, Auth: sessions /* 또는 자체 auth.Provider */})
mux.Handle("/agent/v1/connect", ctl.AgentHandler())
mux.Handle("/api/", http.StripPrefix("/api", ctl.APIHandler()))
mux.Handle("/", web.Handler(web.Options{}))
go ctl.Run(ctx)
```

교체할 수 있는 구성요소는 `auth.Provider`(+`PasswordLogin`/`SessionIssuer`/`ExternalLogin`), `auth.Authorizer`, `store.Store`, `logs.Sink`, 룰 provider 타입, `Hooks`입니다.

## 개발

```sh
make test          # go test -race ./...  (로컬 suricata가 있으면 suricata -T 테스트 포함)
make lint          # golangci-lint
make proto         # proto → Go/TS 코드 생성 (protoc 필요)
make web           # 웹 UI 빌드 (web/dist)
make integration   # Docker + 실제 Suricata E2E (IDS 경보, IPS 차단, 검증 실패, 롤백, 재부팅 복원)
make tap-test      # suritap 단위 테스트 + Go↔Rust 상호운용 + Traefik 플러그인(Yaegi 하네스 포함) (cargo 필요)
make tap SURICATA_SRC=/path/to/suricata-8.0.7        # suritap.so, suritap-mockd, suritap-probe
SURICATA_PREFIX=... SURICATA_SRC=... make tap-integration   # 실제 Suricata로 suritap 검증
make traefik       # suritap 어댑터를 넣은 패치 빌드 Traefik (bin/traefik-suritap)
SURICATA_PREFIX=... SURICATA_SRC=... make tap-traefik       # 공식 Traefik + 플러그인 + 실제 Suricata E2E (--patch: 패치 빌드)
make tap-kong-test # Kong 플러그인의 Lua 클라이언트 테스트 (docker 필요)
SURICATA_PREFIX=... SURICATA_SRC=... make tap-kong          # 공식 Kong 이미지 + 플러그인 + 실제 Suricata E2E
```

| 경로 | 내용 |
|---|---|
| `proto/` | 에이전트 프로토콜(`agent/v1`), 관리 API(`api/v1`) |
| `pkg/` | 공용 패키지: sshkey, noiseconn, wire, bundle, ruleset, yamlmerge, overlay, ringqueue, suritap(Go 클라이언트) |
| `tap/` | suritap Rust 워크스페이스: 프로토콜·Rust 클라이언트(`suritap`), Suricata 플러그인(`suritap-plugin`) |
| `adapters/` | 프록시 어댑터 (`traefik-plugin`: Traefik 플러그인, `traefik`: 패치 빌드용, `kong`: Kong 플러그인) |
| `controller/` | embed 가능한 컨트롤러 |
| `agent/` | 노드 에이전트 |
| `web/` | 웹 UI (`web/ui` 소스, `web/dist` 빌드 결과) |
| `cmd/` | 실행 파일 |
| `deploy/` | Dockerfile, docker-compose |
| `test/` | 통합 테스트 |

## 라이선스

[Mozilla Public License 2.0](LICENSE)
