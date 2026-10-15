# suricontroller 아키텍처 & 구현 계획

> 상태: v0.3 (2026-10-14, 구현 반영)
> 범위: suri-controller / suri-controller-web / suri-node-agent

---

## 0. 요약

- **Go 단일 모듈 모노레포**입니다. `controller/`는 다른 프로그램에 embed할 수 있는 라이브러리이고, `cmd/suri-controller`는 기본 구현을 연결하기만 하는 얇은 main입니다.
- **연결 방향은 Agent → Controller 아웃바운드 하나뿐**입니다.
  `WebSocket(ws/wss) → Noise_IK_25519_ChaChaPoly_BLAKE2s → yamux → length-prefixed protobuf`
  cloudflared나 리버스 프록시가 TLS를 종단해도 E2E 기밀성과 상호 인증이 유지됩니다.
- **키**: OpenSSH `ssh-ed25519` 키를 그대로 쓰고, Noise DH에 쓸 때만 X25519로 변환합니다. age의 ssh-ed25519 recipient와 같은 방식입니다.
- **선언적 동기화**: controller는 노드별 *desired state*만 보냅니다. desired state는 번들 ID, 인터페이스 모드, 로그 정책으로 구성됩니다. agent는 이를 reconcile하고 결과를 보고합니다.
- **룰과 설정은 go-git bare repo 2개**로 관리합니다(`rules.git`, `config.git`). controller는 `(rules_commit, config_commit, node)`을 입력으로 서명된 번들을 만듭니다. suricata-update의 disable/enable/drop/modify 로직은 Go로 포팅해 controller에서 실행하므로 agent에는 Python이 필요 없습니다.
- **Agent**는 엔진 런타임, 방화벽, 호스트 명령 실행을 인터페이스로 추상화합니다. docker profile은 `chroot /host`를 쓰고, 추후 native OpenWRT profile은 procd와 fw4를 씁니다.
- **로그**: 로그 파일 위치는 노드 사용자가 정합니다(Elastic Agent 등 외부 수집기와 병행 가능). agent는 그 파일을 읽어 선택된 것만 보내고, agent와 controller 양쪽에 byte 상한이 있는 drop-oldest 메모리 링 큐를 둡니다. controller는 노드와 로그 타입별로 파일에 저장하고, rotation과 retention janitor로 정리합니다.

---

## 1. 전체 구성

```
 Browser
    │ HTTPS (Connect / JSON)
    ▼
┌───────────────────────────── suri-controller (Go library) ──────────────────────────────┐
│  web.Handler (SPA, go:embed)        APIHandler (Connect)  ── auth.Provider / Authorizer │
│                                          │                                              │
│        ┌──────────────┬──────────────┬───┴──────────┬──────────────┐                    │
│     nodes          rules          config         deploy          logs                   │
│        │              │              │              │              │                    │
│     Store(SQLite)  rules.git      config.git    Renderer ──▶ Bundle cache   LogSink     │
│                    (go-git)       (go-git)                           (File+rotation)    │
│                                                                                         │
│  AgentHandler: WS endpoint → Noise IK → yamux → RPC / log / blob streams                │
└────────────────────────────────────────▲────────────────────────────────────────────────┘
                                         │  wss:// (cloudflared, LB, reverse proxy …)
                                         │  Noise E2E (TLS 종단 위치와 무관)
┌────────────────────────────────────────┴────────────────────────────────────────────────┐
│ suri-node-agent  (docker: network_mode=host, NET_ADMIN/NET_RAW, / → /host)              │
│   conn ── reconcile ── engine(supervisor) ── suricata [ids: af-packet] [ips: nfq]       │
│              │                                                                          │
│              ├── firewall (nftables / fw4 / iptables, chroot /host 로 실행)             │
│              └── collector (eve / suricata.log tail) → ring queue → logs stream         │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

### 1.1 설계 원칙

1. **Agent가 먼저 연결합니다(아웃바운드 전용).** NAT, CGNAT, cloudflared tunnel 환경에서도 동작해야 하기 때문입니다.
2. **Desired state를 reconcile합니다.** 모든 동작은 멱등이어야 하고, 재연결이나 재시작 후에도 같은 결과로 수렴해야 합니다.
3. **로컬 안전 정책은 Agent가 최종 판단합니다.** 인터페이스 allowlist, IPS 허용 여부, 설정 guard가 여기에 해당합니다. controller가 탈취되더라도 피해 범위를 제한하기 위해서입니다.
4. **Last-known-good을 유지합니다.** agent는 마지막으로 성공한 릴리스를 로컬에 보관합니다. 라우터가 재부팅되면 controller 연결 없이도 IDS/IPS를 복원합니다.
5. **IPS는 기본적으로 fail-open입니다.** NFQUEUE의 `bypass`를 사용해서, Suricata 장애가 네트워크 장애로 번지지 않게 합니다.
6. **교체 가능성이 예상되는 지점은 모두 인터페이스로 둡니다.** Auth, Store, LogSink, Rule Provider, Engine Runtime, Firewall, HostExec가 해당됩니다.

---

## 2. 저장소 / 모듈 구조

모듈 경로는 가칭 `github.com/jc-lab/suricontroller`입니다(확정 필요).

```
suricontroller/
├── go.mod
├── buf.yaml / buf.gen.yaml
├── proto/suricontroller/
│   ├── agent/v1/agent.proto        # agent ↔ controller
│   └── api/v1/*.proto              # 웹 관리 API (Connect)
├── gen/                            # protoc 생성물 (go, ts)
├── pkg/                            # controller/agent 공용
│   ├── sshkey/      # ssh-ed25519 파싱/생성/포맷, fingerprint, ed25519→x25519
│   ├── noisews/     # Noise IK handshake over WebSocket, net.Conn 어댑터(분할/재조립)
│   ├── wire/        # yamux 세션, 스트림 타입, uvarint+proto codec, 경량 RPC(Envelope)
│   ├── ringqueue/   # byte 상한 drop-oldest 큐 (+drop 카운터)
│   ├── bundle/      # 번들 포맷(tar.zst + manifest + ed25519 서명) reader/writer
│   ├── ruleset/     # 룰 파서, matcher, disable/enable/drop/modify, flowbits 해석
│   └── yamlmerge/   # yaml.v3 Node 기반 deep-merge (%YAML 1.1 헤더 보존)
├── controller/                     # ★ embed 가능한 공개 라이브러리
│   ├── controller.go               # New(Options), Run, AgentHandler, APIHandler
│   ├── auth/        # Provider, PasswordLogin, Authorizer, StaticAdmin, SessionManager
│   ├── store/       # Store 인터페이스 + sqlite 구현
│   ├── agentgw/     # WS endpoint, 세션 레지스트리, Hello/Status 처리, desired push
│   ├── nodes/       # 노드/키 등록(관리자 사전 등록), 인터페이스 모드
│   ├── gitrepo/     # go-git bare repo 래퍼: TreeBuilder 커밋, log, diff, 파일 읽기
│   ├── rules/       # Provider 인터페이스, et-open, local, 스케줄러
│   ├── configrepo/  # config.git 레이어링(common + nodes/{id})
│   ├── render/      # (rules_commit, config_commit, node) → 번들, 캐시
│   ├── deploy/      # 배포 정책, desired state 계산, 적용 이력
│   ├── logs/        # ingest 큐, 수집 정책, LogSink 인터페이스, FileSink, retention
│   └── api/         # Connect 핸들러
├── agent/
│   ├── agent.go
│   ├── config/      # agent.yaml (controller URL, hostkey pin, 인터페이스, IPS 허용)
│   ├── conn/        # dialer, 재연결(backoff+jitter), proxy, 커스텀 헤더
│   ├── reconcile/   # desired vs applied 상태 머신, 적용 파이프라인
│   ├── platform/    # HostExec, HostFS, Probe(OpenWRT/fw4/offload 감지), Profile
│   ├── firewall/    # Backend 인터페이스: nftables(fw4 포함), iptables, none
│   ├── engine/      # Runtime 인터페이스: supervisor(현재), procd/systemd(향후)
│   │   └── unixsock/  # Suricata unix-command 프로토콜 클라이언트
│   ├── collector/   # source(file tail, process output), 필터, shipper
│   └── state/       # state.json, releases/, current 심링크
├── web/                            # suri-controller-web
│   ├── embed.go                    # go:embed dist → http.Handler
│   └── ui/                         # Vite + React + TS
├── cmd/
│   ├── suri-controller/            # 설정 파일/env/flag → controller.New
│   └── suri-node-agent/            # run | keygen | pubkey | check
├── deploy/
│   ├── agent/      Dockerfile, docker-compose.yml, openwrt.md
│   └── controller/ Dockerfile, docker-compose.yml (cloudflared 예시 포함)
└── docs/
```

> 단일 모듈로 둬도 Go는 import한 패키지만 링크하므로 agent 바이너리에 go-git이나 sqlite가 들어가지 않습니다.
> 패키지 경계는 `pkg/`(공용) → `controller/`, `agent/`(서로 import 금지)로 강제합니다(depguard lint).

---

## 3. 통신 프로토콜 (Agent ↔ Controller)

### 3.1 레이어

```
L5  protobuf (suricontroller.agent.v1)        control RPC / LogBatch / Blob
L4  framing: uvarint length + proto bytes     yamux 스트림마다
L3  yamux                                      다중화, 스트림별 flow control, keepalive
L2  Noise_IK_25519_ChaChaPoly_BLAKE2s          net.Conn 어댑터 (메시지 ≤ 65535B)
L1  WebSocket binary message (coder/websocket) ws:// 또는 wss://
```

- WebSocket은 `websocket.NetConn`으로 byte stream(net.Conn)으로 바꾸고, Noise 메시지마다 **2-byte 길이 prefix**를 붙입니다. 그래서 하위 전송의 메시지 경계에 의존하지 않고, 같은 코드가 TCP나 `net.Pipe`에서도 동작합니다.
- Noise 메시지 최대 크기가 65535B이므로 `Write`할 때 `65535-16(tag)` 단위로 나눕니다. `Read`는 byte stream으로 노출하고, framing은 yamux가 맡습니다.
- **yamux를 쓰는 이유**: 번들 다운로드(수 MB)나 대량 로그가 heartbeat와 제어 메시지를 막지 않게 하려는 것입니다. 스트림별 flow control이 있어서 자연스럽게 backpressure가 생깁니다.
- **gRPC를 쓰지 않는 이유**: 추후 OpenWRT native 패키지가 생기면 플래시 용량에 맞춰 바이너리를 작게 유지해야 합니다. 그래서 `Envelope{id, reply_to, oneof body}` 형태의 경량 RPC를 씁니다.
- **Prologue**는 `"suricontroller/agent/1"`입니다. 프로토콜 버전을 handshake transcript에 묶습니다.

### 3.2 Handshake (Noise IK)

```
agent (initiator)                                         controller (responder)
  │ agent.yaml에 controller hostkey pin (known_hosts 방식)        │
  │── WS Upgrade  GET /agent/v1/connect  (subprotocol suricontroller.v1)
  │── msg1: e, es, s, ss + payload{node_id, agent_version, ts} ─▶│ s(x25519) → 노드 조회
  │                                                              │ - authorized: accept
  │                                                              │ - unknown/disabled: 즉시 reject
  │◀── msg2: e, ee, se + payload{accepted, reason, server_time} ─│
  │══ transport ═════════════════════════════════════════════════│
```

- **IK를 고른 이유**: agent가 controller 공개키를 미리 알고 있으므로 1-RTT로 상호 인증이 끝납니다. initiator identity도 암호화됩니다(WireGuard와 같은 패턴).
- **Replay 대응**: IK msg1은 재전송될 수 있습니다.
  - msg1 payload로 **상태를 바꾸지 않습니다**.
  - 기존 세션은 새 세션이 **첫 transport 메시지(Hello)를 성공적으로 보낸 뒤에만** 교체합니다. 공격자가 msg1을 재전송해 정상 세션을 끊는 것을 막기 위해서입니다.
  - `ts`가 ±5분을 벗어나면 거부합니다. 같은 키에 대해서는 ts가 단조 증가하는지 확인합니다.
- **Unknown key 처리**: 등록되지 않았거나 비활성화된 키는 **즉시 거부**합니다. 노드는 관리자가 UI에서 공개키 라인을 붙여넣어 사전 등록해야 합니다. 거부된 시도는 fingerprint와 함께 controller 로그에 남깁니다.
- **WS 옵션**: 커스텀 헤더를 지원합니다(예: Cloudflare Access service token `CF-Access-Client-Id/Secret`). `HTTPS_PROXY`도 지원합니다. cloudflared/LB의 idle timeout에 대비해 WS ping을 30s마다 보냅니다.
- **재연결**: exponential backoff + jitter(1s → 60s cap)를 씁니다.

### 3.3 키 포맷

| 키 | 위치 | 공개키 표현 |
|---|---|---|
| Controller hostkey | `{data}/hostkey` (OpenSSH private, 0600) | `ssh-ed25519 AAAAC3… suri-controller` |
| Agent clientkey | `/etc/suri-agent/agent_ed25519` | `ssh-ed25519 AAAAC3… <node-id>` |

- 파싱에는 `golang.org/x/crypto/ssh`의 `ParseAuthorizedKey`, `ParseRawPrivateKey`, `MarshalPrivateKey`를 씁니다.
- X25519 변환
  - 공개키: `filippo.io/edwards25519` `Point.BytesMontgomery()`
  - 개인키: `sha512(seed)[:32]` (clamping은 X25519 연산에서 수행)
- UI에는 fingerprint를 `SHA256:…` 형식(`ssh-keygen -lf`와 호환)으로 표시합니다.
- **node-id**는 `^[a-z0-9][a-z0-9._-]{0,62}$`만 허용합니다. git 경로(`nodes/{id}/`)로 쓰이므로 path traversal을 막아야 합니다. `common`, `_`로 시작하는 이름은 예약어입니다.
- 노드의 정식 node-id는 controller에 등록된 키의 comment입니다. handshake의 `node_id`가 이와 다르면 거부합니다.
- (향후) 키 rotation: 기존 세션에서 새 공개키를 제출하고 관리자가 승인하는 방식입니다.

### 3.4 스트림

| 스트림 | 개설 주체 | 용도 |
|---|---|---|
| `control` | agent, 세션당 1 | Envelope RPC: Hello, DesiredState, ApplyReport, Status … |
| `logs` | agent, 1 | `LogBatch` (zstd 압축 배치) |
| `blob` | agent, 다운로드마다 | `BlobRequest{bundle_id, offset}` → raw bytes (재개 가능) |

### 3.5 메시지 스케치 (`agent/v1/agent.proto`)

```proto
syntax = "proto3";
package suricontroller.agent.v1;

message Envelope {
  uint64 id = 1;        // 요청 ID (notification은 0)
  uint64 reply_to = 2;
  oneof body {
    Hello hello = 10;
    HelloAck hello_ack = 11;
    DesiredState desired_state = 12;
    ApplyReport apply_report = 13;
    StatusReport status = 14;
    Error error = 15;
  }
}

message Hello {
  string node_id = 1;
  string agent_version = 2;
  PlatformInfo platform = 3;          // os, os_version, arch, profile(docker/native), firewall backend
  EngineInfo engine = 4;              // suricata version, features(nfq, af-packet, hyperscan…)
  repeated InterfaceInfo interfaces = 5;  // agent.yaml 에 허용된 인터페이스만
  AppliedState applied = 6;
  repeated Warning warnings = 7;      // flow offloading 감지, shadowed keys 등
}

message InterfaceInfo {
  string name = 1;
  bool ips_allowed = 2;               // agent 로컬 설정이 결정
  bool present = 3;
  bool up = 4;
}

enum InterfaceMode {
  INTERFACE_MODE_UNSPECIFIED = 0;
  INTERFACE_MODE_OFF = 1;
  INTERFACE_MODE_IDS = 2;
  INTERFACE_MODE_IPS = 3;
}

message BundleRef {
  string bundle_id = 1;               // sha256(bundle)
  string rules_commit = 2;
  string config_commit = 3;
  uint64 size = 4;
}

message DesiredState {
  uint64 generation = 1;              // 구성요소 중 하나라도 바뀌면 +1
  BundleRef bundle = 2;
  map<string, InterfaceMode> interface_modes = 3;
  LogCollectionPolicy log_policy = 4;
}

message AppliedState {
  uint64 generation = 1;
  BundleRef bundle = 2;
  map<string, InterfaceMode> interface_modes = 3;
}

enum ApplyStage {
  APPLY_STAGE_UNSPECIFIED = 0;
  POLICY = 1;      // 허용 범위 검사 (인터페이스/IPS/guard)
  DOWNLOAD = 2;
  VERIFY = 3;      // sha256, 서명
  RENDER = 4;      // yaml 병합
  VALIDATE = 5;    // suricata -T
  FIREWALL = 6;
  ACTIVATE = 7;    // reload-rules 또는 restart
  HEALTHCHECK = 8;
}

enum ApplyStatus {
  APPLY_STATUS_UNSPECIFIED = 0;
  IN_PROGRESS = 1;
  SUCCEEDED = 2;
  FAILED = 3;        // 이전 상태 유지
  ROLLED_BACK = 4;   // 적용 후 실패 → 이전 릴리스로 복구
}

message ApplyReport {
  uint64 generation = 1;
  ApplyStatus status = 2;
  ApplyStage stage = 3;
  string message = 4;
  string detail = 5;                  // suricata -T 출력 tail 등
  repeated RuleError rule_errors = 6; // 파싱 실패 룰 (sid, file, line, error)
  AppliedState applied = 7;           // 현재 실제로 동작 중인 상태
  int64 started_at_unix_ms = 8;
  int64 finished_at_unix_ms = 9;
}

message LogBatch {
  uint64 seq = 1;
  LogType type = 2;                   // EVE, SURICATA_LOG, FAST, STATS, AGENT
  string instance = 3;                // ids | ips
  bytes zstd_records = 4;             // \n 구분 레코드
  uint64 dropped_since_last = 5;
}
```

### 3.6 세션 흐름

```
agent                                              controller
  │── [control] Hello(applied, ifaces, engine) ────▶│ 세션 등록, 노드 facts 저장
  │◀──────────── HelloAck + DesiredState(gen=N) ─────│
  │── [blob] BlobRequest(bundle_id, offset) ───────▶│
  │◀──────────────────────── bundle bytes ───────────│
  │── ApplyReport(N, IN_PROGRESS, VALIDATE) ───────▶│
  │── ApplyReport(N, SUCCEEDED) ───────────────────▶│ applied/이력 갱신
  │── StatusReport (30s 주기: 엔진/패킷/드롭/큐) ──▶│
  │── [logs] LogBatch … ───────────────────────────▶│ ingest 큐 → LogSink
  │◀──────────── DesiredState(gen=N+1) ──────────────│ (정책/커밋/모드 변경 시 push)
```

---

## 4. suri-controller

### 4.1 Embeddable 라이브러리 API

```go
package controller

type Options struct {
	DataDir    string
	HostKey    ed25519.PrivateKey // nil → {DataDir}/hostkey 로드/생성
	Store      store.Store        // nil → SQLite({DataDir}/controller.db)
	Auth       auth.Provider      // 필수 (cmd 에서는 StaticAdmin)
	Authorizer auth.Authorizer    // nil → 인증된 사용자 전체 허용
	LogSink    logs.Sink          // nil → FileSink({DataDir}/logs)
	Providers  []rules.Provider   // nil → [et-open, local]
	Logger     *slog.Logger
	Hooks      Hooks              // NodeConnected, ApplyFailed … 콜백
}

func New(opts Options) (*Controller, error)

func (c *Controller) Run(ctx context.Context) error // 스케줄러, janitor, 렌더 워커
func (c *Controller) AgentHandler() http.Handler    // WS endpoint
func (c *Controller) APIHandler() http.Handler      // Connect 서비스 (auth middleware 포함)

// Go에서 직접 호출할 수 있는 서비스 계층 (Connect 핸들러도 이것을 호출)
func (c *Controller) Nodes() *nodes.Service
func (c *Controller) Rules() *rules.Service
func (c *Controller) Config() *configrepo.Service
func (c *Controller) Deploy() *deploy.Service
func (c *Controller) Logs() *logs.Service
```

embed 하는 쪽은 자기 mux에 붙여서 씁니다.

```go
mux.Handle("/suri/agent/", http.StripPrefix("/suri", ctl.AgentHandler()))
mux.Handle("/suri/api/", http.StripPrefix("/suri/api", ctl.APIHandler()))
mux.Handle("/suri/", http.StripPrefix("/suri", web.Handler(web.Options{APIBase: "/suri/api"})))
```

### 4.2 인증

```go
package auth

type Principal struct {
	ID          string
	DisplayName string
	Roles       []string
	Attrs       map[string]string
}

// Provider: HTTP 요청 → Principal. 세션 쿠키, bearer 토큰, 프록시 헤더, OIDC 등 자유롭게 구현.
type Provider interface {
	Authenticate(r *http.Request) (*Principal, error)
}

// PasswordLogin: ID/PW 로그인을 지원하는 Provider 가 추가로 구현 (선택).
// 미구현 Provider 는 웹 UI 가 로그인 폼 대신 LoginURL() 로 리다이렉트.
type PasswordLogin interface {
	Login(ctx context.Context, username, password string) (*Principal, error)
}

type ExternalLogin interface {
	LoginURL(returnTo string) string
}

type Authorizer interface {
	Authorize(ctx context.Context, p *Principal, action Action, resource string) error
}
```

- **현재 구현**: `auth.NewStaticAdmin(username, password)` + `SessionManager`.
  - `SessionManager`는 HMAC 서명 쿠키를 씁니다(HttpOnly, Secure, SameSite=Strict).
  - 비밀번호는 constant-time으로 비교하고, 로그인 시도에 rate limit을 겁니다.
  - env: `SURICONTROLLER_ADMIN_USERNAME`, `SURICONTROLLER_ADMIN_PASSWORD`. bcrypt 해시를 쓰려면 `…_PASSWORD_HASH`를 지정합니다.
- **CSRF**: Connect 요청은 `Content-Type: application/json`과 `Connect-Protocol-Version` 헤더가 필요합니다. 이 조건과 SameSite=Strict로 기본 방어가 됩니다.
- **감사**: UI에서 룰이나 설정을 수정하면 git commit author를 Principal로 기록합니다. 별도 audit 테이블에도 남깁니다.

### 4.3 Store

- 기본 구현은 SQLite입니다(`modernc.org/sqlite`, CGO 불필요, 크로스컴파일 용이). `store.Store` 인터페이스로 감싸서 embedder가 Postgres 등으로 바꿀 수 있습니다.
- 주요 테이블
  - `nodes`: node_id, pubkey, fingerprint, enabled, facts json, last_seen
  - `node_interfaces`: node_id, name, ips_allowed(reported), mode(desired)
  - `node_state`: desired_generation, desired bundle, applied bundle, applied_at, last_status, last_error
  - `apply_history`: node_id, generation, rules/config commit, status, stage, message, started/finished
  - `deploy_policies`: kind(rules/config), mode, pinned_commit, effective_commit
  - `providers`: name, type, enabled, interval, options json, last_fetch state
  - `log_policies`: scope(global/node), policy json
  - `retention_policies`, `settings`, `audit_log`

### 4.4 Git 저장소 (go-git)

- 저장소는 `{data}/git/rules.git`, `{data}/git/config.git`이고, 둘 다 **bare repo**입니다.
- **쓰기는 worktree 없이 `TreeBuilder`로 합니다.**
  1. base commit에 변경 세트(path → content | delete)를 적용해 tree/commit object를 직접 만듭니다.
  2. `refs/heads/main`을 compare-and-swap으로 갱신합니다.
  - UI 편집 요청에는 base commit이 함께 오므로, 그사이 HEAD가 바뀌었으면 충돌로 처리합니다.
  - 저장소마다 writer를 mutex로 하나만 둡니다.
  - worktree status 계산(대용량 룰 파일 해싱)과 동시성 문제를 피하려는 선택입니다.
- **commit author**는 UI 사용자 Principal 또는 `suricontroller-bot`(provider 동기화)입니다.
- **유지보수**: ET 룰은 수 MB짜리 파일이 매일 바뀝니다. loose object가 쌓이지 않도록 주기적으로 `RepackObjects`를 실행합니다. pinned commit과 배포 이력에 있는 commit은 GC에서 보호합니다.
- (향후) git smart-HTTP를 노출해 GitOps 방식으로 clone/push할 수 있게 합니다. push는 검증 hook을 거칩니다.

#### rules.git — `/{provider}/{rule files…}`

```
/et-open/emerging-*.rules
/et-open/classification.config
/et-open/reference.config
/local/*.rules            # UI 에서 편집하는 사용자 룰 (local provider)
/{custom}/...             # (향후) URL provider
```

```go
type Provider interface {
	Name() string // = 디렉터리 이름
	Fetch(ctx context.Context, prev FetchState) (*FetchResult, error) // 변경 없으면 ErrNotModified
}
```

- **et-open**
  - URL: `https://rules.emergingthreats.net/open/suricata-{ver}/emerging.rules.tar.gz`
  - `.md5`를 먼저 받아 변경 여부를 확인하고, 바뀌었으면 tar.gz를 받아 `rules/`만 `/et-open/`에 반영합니다. tree가 실제로 달라졌을 때만 커밋합니다.
  - 설정: `enabled`, `interval`(기본 24h + jitter), `suricata_version`, 수동 `SyncNow`.
  - **노드마다 Suricata 버전이 다른 경우**: provider 인스턴스를 여러 개 둡니다(`et-open-7.0`, `et-open-8.0`). 노드별 `sources.yaml`로 어느 것을 쓸지 고릅니다.
- **local**: UI 편집기로 파일을 CRUD하고 커밋합니다.

#### config.git — Suricata 설정 (controller 자신의 설정 아님)

```
/common/
    suricata.yaml        # Suricata 설정 overlay (controller 관리 부분만)
    sources.yaml         # 사용할 provider / 파일 glob 선택
    disable.conf
    enable.conf
    drop.conf
    modify.conf
    threshold.config
/nodes/{node-id}/        # 노드별 override (필요한 파일만)
    suricata.yaml
    disable.conf
    ...
```

| 파일 | common + node 병합 규칙 |
|---|---|
| `suricata.yaml` | deep merge (map은 재귀, list는 교체), node 우선 |
| `sources.yaml` | node 파일이 있으면 교체 |
| `disable/enable/drop/modify.conf` | 이어붙이기 (common 먼저). 처리 순서가 disable→enable→drop→modify이므로 node의 `enable.conf`로 common의 disable을 되돌릴 수 있음 |
| `threshold.config` | 이어붙이기 |
| 공통 | node 파일 첫 줄이 `# suricontroller: replace`이면 common 무시 |

### 4.5 렌더러 & 번들

입력 `(rules_commit, config_commit, node_id, node facts)` → 출력 **번들**

1. config tree에서 `common/*`, `nodes/{node_id}/*`를 읽어 위 규칙대로 병합합니다.
2. `sources.yaml`에 따라 rules tree에서 대상 provider와 파일을 고릅니다. 기본값은 활성화된 모든 provider입니다.
3. `pkg/ruleset` (suricata-update 1.3.0 포팅, ET Open 전체와 byte 단위로 일치하는지 golden test로 검증)
   - suricata-update와 같은 방식으로 소스 파일을 읽습니다(`ParseFiles`). 파일명 순서로 처리하고, `*deleted.rules`는 무시합니다. dataset 파일은 `datasets/<md5>`로 재작성해 번들에 함께 넣습니다.
   - 룰을 파싱합니다. 주석 처리된(비활성) 룰도 인식합니다.
   - `group:` matcher는 파일 basename에, `filename:` matcher는 `{provider}/{file}` 경로에 매칭합니다.
   - 잘못된 conf 라인은 suricata-update처럼 경고만 하고 넘기지 않고 **오류로 거부**합니다(`ValidateConfig`). UI에서 커밋하기 전에 검증하는 데 씁니다.
   - suricata-update와 같은 의미로 disable → enable → drop → modify를 적용하고, 끝으로 **flowbits 의존 룰을 자동 활성화**합니다(noalert).
   - matcher는 `gid:sid`, `sid`, `re:`, `group:`(파일 glob), `metadata: key value`를 지원합니다.
   - modify는 `matcher "from" "to"` 형식이고, Python 정규식 backref `\1`을 Go `${1}`로 변환합니다.
4. 출력
   ```
   manifest.json        # rules_commit, config_commit, node_id, created_at, files[sha256], stats
   manifest.sig         # controller hostkey(ed25519) 서명
   rules/suricata.rules # 병합/변환된 단일 룰 파일
   rules/classification.config, reference.config, threshold.config
   config/controller.yaml   # 병합된 suricata.yaml overlay
   ```
5. `tar` + `zstd`(klauspost/compress)로 묶습니다.
   - **`bundle_id = sha256(manifest.json)`**입니다. manifest에 모든 파일의 sha256이 들어 있으므로 압축 방식과 무관한 content-addressed ID가 됩니다.
   - 그래서 controller가 재시작하거나 압축기 버전이 바뀌어도 같은 내용이면 같은 ID가 나오고, 노드가 불필요하게 재적용하지 않습니다.
   - 아카이브는 `{data}/bundles/{id}.tar.zst`에 캐시하고, 키 `(rules_commit, config_commit, node_id)`는 메모리에서 인덱싱합니다. 노드가 참조하지 않는 번들은 GC가 지웁니다.
   - 노드는 자기에게 desired로 지정된 번들만 받을 수 있습니다. 다른 노드의 설정이 유출되지 않게 하기 위해서입니다.
6. **Preview API**: 특정 노드에 적용될 effective config와 룰 통계(활성/비활성/drop/modify 수, flowbits로 켜진 수)를 UI에서 미리 볼 수 있게 합니다.

> **controller에서 렌더링하는 이유**: 중앙에서 미리보기와 검증을 할 수 있고, 결과가 결정적이어서 노드별 버전 추적이 쉽습니다. agent에 suricata-update(Python)가 필요 없으므로 OpenWRT native 설치에도 유리합니다.
> `pkg/ruleset`은 ET Open 전체를 대상으로 suricata-update 결과와 비교하는 **golden test**로 동등성을 보장합니다.

### 4.6 배포 정책 & 버전 관리

룰과 설정에 **각각** 다음 정책을 둡니다.

```
mode: auto | pinned | paused
pinned_commit: <commit-id>
effective_commit: (계산값, 저장)
```

| mode | effective_commit | 용도 |
|---|---|---|
| `auto` | HEAD (새 커밋마다 갱신) | 기본. ET 자동 업데이트가 노드까지 반영 |
| `pinned` | 지정 commit | 자동 배포를 멈추고 이전 commit으로 롤백하거나 특정 버전에 고정 |
| `paused` | 현재 값으로 동결 | 배포 비활성화. 신규 노드도 동결 버전을 받음 |

- ET Open 다운로드(provider enabled)와 노드 배포(deploy mode)는 **서로 독립적인 스위치**입니다. 어떤 provider의 룰을 배포할지는 config.git의 `sources.yaml`로 고릅니다.
- 첫 실행에서 ET Open을 비활성으로 두려면 `SURICONTROLLER_ET_OPEN=false`를 설정합니다(air-gapped 환경).
- 노드별 desired state는 다음과 같이 계산합니다.
  ```
  bundle          = render(rules.effective, config.effective, node)
  interface_modes = node 설정 (agent가 보고한 허용 범위로 검증)
  log_policy      = node override ?? global
  generation      = 위 요소가 바뀔 때마다 +1
  ```
- 정책 변경, HEAD 변경(auto), 모드 변경, 노드 연결 시 desired를 다시 계산하고, 연결된 노드에 push합니다. 오프라인 노드는 다음 접속 때 Hello에 대한 응답으로 받습니다.
- **노드별 버전 표시**: desired와 applied commit(rules/config 각각), 상태, drift 여부(applied ≠ effective), 실패 원인을 보여줍니다. `apply_history`로 타임라인을 남깁니다.
- 인터페이스 모드 변경은 배포 정책과 무관하게 즉시 반영합니다. 번들은 그대로이고 agent 측 runtime 설정만 바뀝니다.
- (향후) 노드별 pin override로 canary 배포를 하고, 단계적 rollout을 지원합니다.

### 4.7 로그 수집 (controller 측)

- **수집 정책**: global 기본값 위에 노드별 override(`inherit` 또는 `custom`)를 둡니다.
  - 타입: `eve`(event_type별: alert, anomaly, drop, flow, dns, http, tls, fileinfo, stats …), `suricata.log`, `fast.log`, `stats.log`, `agent.log`
  - UI는 노드 × 타입 행렬이고, 행과 열 단위 **전체 선택/해제**, `inherit` 토글을 제공합니다.
- **Ingest 경로**: 세션별 reader → `ringqueue`(전역 `max_bytes` 설정, 가득 차면 **오래된 것부터 삭제**, drop 카운터 유지) → writer worker → `LogSink`
  ```go
  type Sink interface {
  	Write(ctx context.Context, nodeID string, t LogType, records [][]byte) error
  	Close() error
  }
  ```
  embedder는 ES, Loki, Kafka로 보내는 sink를 직접 구현하거나 여러 sink를 묶어 쓸 수 있습니다.
- **FileSink**(기본)
  ```
  {data}/logs/{node-id}/{type}/{YYYYMMDD}/{type}-{HH}.log      # 열린 segment
  {data}/logs/{node-id}/{type}/{YYYYMMDD}/{type}-{HH}.log.zst  # 닫힌 segment
  ```
- **Rotation/Retention**(global + 노드별 override)
  - `rotate: hourly | daily | size(N MB)`
  - `max_age`, `max_bytes_per_node`, `max_bytes_total`
  - janitor가 5분마다 조건을 넘은 segment를 오래된 순으로 삭제합니다.
- **UI**: 노드/타입별 파일 목록, 실시간 tail(server-streaming), 다운로드, 간단한 문자열 필터를 제공합니다.

### 4.8 관리 API (Connect, `api/v1`)

| 서비스 | 주요 RPC |
|---|---|
| `AuthService` | GetAuthInfo(로그인 방식), Login, Logout, Me |
| `NodeService` | ListNodes, GetNode, AddNode(공개키 라인), Enable/Disable/RemoveNode, SetInterfaceModes, ListApplyHistory |
| `RuleService` | ListProviders, UpdateProvider, SyncNow, ListCommits, GetCommitDiff, Read/WriteLocalRuleFile, Get/SetDeployPolicy |
| `ConfigService` | ListTree, ReadFile, WriteFiles(base_commit, changes, message), ListCommits, Diff, PreviewNode, Get/SetDeployPolicy |
| `LogService` | Get/SetCollectionPolicy(global/node), ListLogFiles, TailLog(stream), DownloadLog, Get/SetRetention, GetQueueStats |
| `SystemService` | GetInfo(hostkey 공개키 라인, 버전), GetSettings, UpdateSettings |

Connect를 고른 이유는 세 가지입니다. agent 프로토콜과 같은 buf 툴체인으로 Go 서버와 TS 클라이언트 타입을 함께 생성할 수 있고, HTTP/1.1 + JSON으로 동작해 curl이나 프록시 친화적이며, 서버 스트리밍(tail)을 지원합니다.

### 4.9 Controller 설정 파일 (`suricontroller.yaml`)

controller 자체 설정입니다. 런타임에 UI로 바꾸는 값(정책, provider, 보존 기간)은 Store에 저장합니다.

```yaml
listen: ":8080"
data_dir: /var/lib/suricontroller
public_path_prefix: ""         # 리버스 프록시 하위 경로
admin:
  username: admin              # env 우선
  password_hash: "$2a$…"
logs:
  ingest_queue_max_bytes: 64MiB
```

---

## 5. suri-controller-web

- 스택: **Vite + React + TypeScript**, `@connectrpc/connect-web`, TanStack Query, Mantine(관리 UI 컴포넌트), CodeMirror 6(yaml/rules 편집 + diff).
- 빌드 결과를 `web/dist`에 두고 `go:embed`해서 `web.Handler()`로 제공합니다. `cmd/suri-controller`가 기본으로 `/`에 마운트합니다. embed하는 쪽은 생략하거나 자체 UI를 쓸 수 있습니다.
- 화면
  1. **로그인**: `GetAuthInfo`에 따라 ID/PW 폼을 보여주거나 외부 로그인으로 보냅니다.
  2. **대시보드**: online/offline 노드, 버전 drift, 최근 적용 실패, 로그 ingest와 drop 통계
  3. **노드**: 목록(상태, desired/applied 버전, last seen), 공개키 라인으로 노드 등록
     - 상세 화면에는 **인터페이스 표**가 있고 Off/IDS/IPS를 고릅니다. `ips_allowed=false`인 인터페이스는 IPS를 고를 수 없습니다.
     - 그 밖에 엔진 상태와 통계, 적용 이력, 경고(flow offload, shadowed keys)를 보여줍니다.
  4. **룰**: provider 설정(ET Open on/off, 주기, 버전, 지금 동기화, 마지막 결과), 커밋 목록과 diff, 배포 정책(auto/pinned/paused, "이 커밋으로 배포"), local 룰 편집기
  5. **설정**: `common/`, `nodes/{id}/` 트리 편집기, 커밋 메시지, 이력/diff, 롤백(pin), 노드별 렌더 미리보기
  6. **로그**: 수집 정책 행렬(전체/노드별 선택), 로그 브라우저(tail, 다운로드), rotation/retention 설정
  7. **시스템**: controller hostkey 공개키(agent 설정에 복사용), ingest 큐 설정과 상태

---

## 6. suri-node-agent

### 6.1 내부 구조

```
            ┌────────── agent ──────────────────────────────────────────────┐
 controller │ conn ──▶ reconcile ──▶ state (releases/, state.json)          │
  ◀════════▶│   ▲          │                                                │
            │   │          ├──▶ engine.Runtime ──▶ suricata(ids) / (ips)   │
            │   │          ├──▶ firewall.Backend ──▶ HostExec(nft/iptables) │
            │   │          └──▶ collector.Manager ──▶ ringqueue ──▶ shipper │
            │   └──────────────────────────────────────────────────┘        │
            │ platform: Profile{HostExec, HostFS, Probe, Paths}             │
            └───────────────────────────────────────────────────────────────┘
```

### 6.2 플랫폼 추상화 (docker ↔ native)

```go
package platform

// HostExec: 호스트 도구 실행. docker: chroot /host, native: 직접 실행.
type HostExec interface {
	Run(ctx context.Context, name string, args []string, stdin io.Reader) (Result, error)
	LookPath(name string) (string, error)
}

// HostFS: 호스트 파일 접근. docker: /host prefix, native: /.
type HostFS interface {
	ReadFile(path string) ([]byte, error)
	WriteFileAtomic(path string, data []byte, perm fs.FileMode) error
	Stat(path string) (fs.FileInfo, error)
}

type Probe struct {
	OS, OSVersion, Arch string
	OpenWrt             bool // /etc/openwrt_release
	Fw4, Nft, Iptables  bool
	FlowOffload         FlowOffloadState // uci firewall.@defaults[0].flow_offloading(_hw)
}

type Profile struct {
	Name    string // docker | openwrt-native | systemd-native
	Exec    HostExec
	FS      HostFS
	Paths   Paths  // 설정/상태/런타임/로그 경로
	Engine  engine.Runtime
	Firewall firewall.Backend
}
```

```go
package engine

type Runtime interface {
	Info(ctx context.Context) (EngineInfo, error)                       // --build-info: 버전, NFQ/AF_PACKET 지원
	Validate(ctx context.Context, spec InstanceSpec) (*ValidationResult, error) // suricata -T
	Ensure(ctx context.Context, specs []InstanceSpec) error             // 원하는 인스턴스 집합으로 수렴
	ReloadRules(ctx context.Context, instance string) error             // unix-command reload-rules
	Status(ctx context.Context) ([]InstanceStatus, error)
	Output() <-chan LogLine                                             // stdout/stderr (suricata.log)
}

type InstanceSpec struct {
	Name       string      // "ids" | "ips"
	Capture    CaptureMode // AFPacket | NFQ
	Interfaces []string    // AFPacket
	Queues     []uint16    // NFQ
	ConfigPath string      // effective yaml
	ConfigHash string      // 변경 감지 → restart 필요 여부
}
```

```go
package firewall

type Backend interface {
	Name() string
	Apply(ctx context.Context, plan IPSPlan) error           // 원자적 적용
	Check(ctx context.Context, plan IPSPlan) (bool, error)   // 존재/일치 여부 (재적용 판단)
	Remove(ctx context.Context) error
}

type IPSPlan struct {
	Interfaces []string
	Queues     QueueRange
	FailOpen   bool   // NFQUEUE bypass
	Hooks      Hooks  // Forward / Input / Output
}
```

| 구성요소 | docker profile (현재) | openwrt-native (향후) | systemd-native (향후) |
|---|---|---|---|
| HostExec | `chroot /host …`, 호스트에 없으면 이미지 내장 도구로 fallback | 직접 실행 | 직접 실행 |
| HostFS | `/host` prefix | `/` | `/` |
| Engine | `supervisor` (agent가 suricata를 자식 프로세스로 실행) | `procd` (`/etc/init.d/suricata`, ubus) 또는 supervisor | `systemd` 또는 supervisor |
| Firewall | auto: nftables(fw4 포함) → iptables | nftables(fw4) | nftables / iptables |
| 기본 경로 | `/etc/suri-agent`, `/var/lib/suri-agent`, `/run/suri-agent` | `/etc/suri-agent`, `/var/lib/suri-agent`(overlay), `/tmp/suri-agent` | FHS |

### 6.3 Agent 로컬 설정 (`/etc/suri-agent/agent.yaml`)

인터페이스 목록과 IPS 허용 여부는 **agent 쪽에서만** 정합니다.

```yaml
node_id: router-01                 # 키 comment 와 일치해야 함
key_file: /etc/suri-agent/agent_ed25519

controller:
  url: wss://suri.example.com/agent/v1/connect
  host_key: "ssh-ed25519 AAAAC3… suri-controller"
  headers:                         # 예: Cloudflare Access service token
    CF-Access-Client-Id: "…"
    CF-Access-Client-Secret: "…"

platform:
  profile: docker                  # docker | openwrt-native | systemd-native
  host_root: /host
  firewall: auto                   # auto | nftables | iptables | none

interfaces:                        # 이 목록 밖의 인터페이스는 controller가 지정할 수 없음
  - name: br-lan
  - name: eth1
    ips: false                     # 인터페이스별 override (기본값은 ips.enabled)

tap:                               # (선택) suritap: TLS 종단 프록시의 평문 검사
  enabled: true
  socket_dir: /run/suritap         # 프록시와 공유
  endpoints:                       # controller가 Off / Detect / Prevent를 정할 수 있는 엔드포인트
    - name: websecure
    - name: admin
      prevent: false

ips:
  enabled: true                    # false → 모든 인터페이스 IDS만 가능
  queues: "0-1"
  fail_open: true                  # NFQUEUE bypass

suricata:
  base_config: /etc/suricata/suricata.yaml   # 사용자 소유, 자유 편집
  local_rules_dir: /etc/suricata/rules.local # 사용자 로컬 룰 (항상 포함)
  allow_lua: false                            # true 일 때만 lua 룰/출력 허용
  instances:                                  # 인스턴스별 로그 디렉터리 (default-log-dir 로 강제)
    ids: { log_dir: /var/log/suricata/ids }
    tap: { log_dir: /var/log/suricata/tap }
    ips: { log_dir: /var/log/suricata/ips }

logs:
  queue_max_bytes: 16MiB           # 메모리 링 큐 (가득 차면 오래된 것부터 삭제)
  start_position: end              # 처음 발견한 파일: end | beginning
  extra_sources:                   # (선택) 자동 탐지 외에 추가로 읽을 파일
    - { type: eve, path: /var/log/suricata/custom-eve.json }
  rotation:                        # (선택) agent 가 로컬 로그 파일을 rotation (rename + SIGHUP)
    enabled: true                  # 외부 logrotate / suricata rotate-interval 을 쓰면 false
    max_size: 64MiB
    keep: 2
```

### 6.4 Suricata 설정 레이어링 (사용자 자유 편집과 공존)

```
① user base   /etc/suricata/suricata.yaml               사용자 자유 편집
② managed     releases/{bundle}/config/controller.yaml  config.git 렌더 결과
③ runtime     agent 생성                                캡처/인터페이스/룰 경로/agent 로그 출력/unix-command
                          우선순위: ③ > ② > ①
        ──▶ agent 가 deep-merge ──▶ /run/suri-agent/{instance}/suricata.yaml ──▶ suricata -c …
```

- Suricata의 `--include`는 "메인 파일 끝에 붙인 것처럼" 로드한다는 설명만 있고, **list(sequence) 병합 의미는 문서화되어 있지 않습니다.** af-packet 인터페이스 list처럼 list가 섞인 설정에서는 결과를 예측하기 어렵습니다. 그래서 병합은 agent가 직접 합니다(`pkg/yamlmerge`, map은 재귀 병합, list는 교체).
- **Shadowed keys**: 사용자가 ①에서 설정했지만 ②나 ③에 덮인 키를 찾아 경고로 보고하고 UI에 표시합니다. "중복되지 않는 범위에서 자유 편집"을 사용자에게 보여주는 장치입니다.
- **Guard**: ② controller overlay에 다음 키가 있으면 POLICY 단계에서 거부합니다.
  - 금지 키: `plugins`, `include`, `unix-command`, `af-packet`, `nfq`, `security.lua.*`
  - 로그 위치/형식은 노드 사용자 소유이므로 `default-log-dir`, `logging`, `outputs`도 금지 키입니다. `outputs`는 list라서 overlay에 넣으면 사용자 출력 전체를 덮어쓰게 됩니다.
  - `outputs`의 파일 경로가 로그 디렉터리 밖이면 거부합니다.
  - controller가 탈취되어도 노드에서 임의 코드가 실행되지 않도록 하기 위한 것입니다.
- **Lua**: Suricata 8은 `security.lua.allow-rules`를 기본으로 켭니다(sandbox). 그래서 runtime 레이어가 `allow_lua`가 꺼져 있으면 이 값을 `no`로 강제합니다. `security.lua.allow-rules`는 agent 로컬 설정 `allow_lua`로만 켤 수 있습니다. 꺼져 있으면 번들 룰에 `lua:`/`luajit:` 키워드가 있을 때 거부합니다. 최근 Lua 관련 CVE(예: CVE-2026-45763, 8.0.5에서 수정)가 있으므로 이미지는 8.0.5 이상으로 고정합니다.
- 사용자 로컬 룰 `local_rules_dir/*.rules`는 ③에서 `rule-files`에 항상 추가합니다.
- **설정 파일은 두 벌입니다.**
  - staging: `releases/{id}/rules`를 직접 가리키며, `-T` 검증용입니다.
  - running: 안정 경로 `active/rules`(심링크 `active → releases/{id}`)를 가리킵니다.
  - 그래서 룰만 바뀌면 running 설정 내용이 그대로입니다. 인스턴스를 재시작하지 않고 심링크만 교체한 뒤 `reload-rules`합니다.
  - 인스턴스 재시작 여부는 running 설정 해시(+캡처 인자)가 바뀌었는지로 판단합니다.
- 사용자가 ① base 설정이나 로컬 룰을 고치면 agent가 30초 주기로 감지합니다. 이어서 `-T` 검증 → 적용(재시작 또는 reload) 순으로 반영하고, 검증에 실패하면 기존 설정을 유지한 채 경고(`local_config_invalid`)를 보고합니다.
- 사용자 설정의 상대 경로 `include`는 effective 설정 파일 위치가 달라도 동작하도록 절대 경로로 바꿉니다.

### 6.5 인터페이스 모드 & 캡처 토폴로지

- controller가 요청한 모드가 허용 범위(인터페이스 목록, `ips` 허용)를 벗어나면 `ApplyReport{FAILED, stage=POLICY}`를 보내고 기존 상태를 유지합니다. controller와 UI에서도 같은 검증을 하지만, 최종 판단은 agent가 합니다.
- **Suricata 한 프로세스는 runmode를 하나만 쓸 수 있습니다.** af-packet(`-i`)과 NFQ(`-q`)를 함께 지정하면 "more than one run mode" 오류가 납니다. 그래서 엔진 인스턴스를 다음과 같이 계획합니다.

| 모드 조합 | 엔진 인스턴스 |
|---|---|
| IDS만 | `ids` 1개: af-packet (IDS 인터페이스들) |
| IPS만 | `ips` 1개: NFQ (queue 0..N) |
| 혼합 | `ids` + `ips` 2개. 룰셋을 두 번 로드하므로 메모리가 약 2배 (Status에 메모리 사용량 표시) |
| 전부 Off | 엔진 중지 |
| `tap.enabled` | 위와 별도로 `tap` 1개: suritap 캡처 플러그인(`--capture-plugin=suritap`). 프록시 엔드포인트 모드와 무관하게 실행되고, 모드는 정책 파일로만 바뀐다(재시작 없음, [suritap.md](suritap.md) §10) |

- **IPS 방화벽 (nftables)**: 전용 테이블을 씁니다.
  ```
  table inet suricontroller {
    chain forward {
      type filter hook forward priority filter + 10; policy accept;
      iifname { "br-lan" } queue flags bypass,fanout to 0-1
      oifname { "br-lan" } queue flags bypass,fanout to 0-1
    }
    chain input  { type filter hook input  priority filter + 10; policy accept;
      iifname { "br-lan" } queue flags bypass,fanout to 0-1 }
    chain output { type filter hook output priority filter + 10; policy accept;
      oifname { "br-lan" } queue flags bypass,fanout to 0-1 }
  }
  ```
  - `priority filter + 10`: fw4(filter 0)가 accept한 트래픽만 검사합니다. 이미 drop될 트래픽은 볼 필요가 없습니다.
  - `bypass`: NFQ listener가 없으면 그대로 통과시킵니다(fail-open). `fail_open: false`면 bypass를 빼서 fail-closed로 동작합니다.
  - **독립 테이블이므로** fw4 reload(`table inet fw4`만 다시 씀)의 영향을 받지 않습니다. agent는 주기적으로 `Check`를 돌려 테이블이 사라졌으면 다시 적용하고, 종료할 때 제거합니다.
  - `nft -f`는 트랜잭션이라 원자적으로 적용됩니다.
  - iptables backend는 `SURICONTROLLER` 체인에 `-j NFQUEUE --queue-balance 0:1 --queue-bypass`를 넣습니다.
- **OpenWRT 주의사항**: software/hardware flow offloading이 켜져 있으면 established flow가 netfilter와 CPU를 우회하므로 IDS/IPS가 사실상 무력화됩니다. agent가 이를 감지해 경고로 보고합니다(자동으로 끄지는 않음).
- **NFQUEUE 커널 지원**: IPS에는 nftables `queue`(nft_queue, iptables는 xt_NFQUEUE)와 nfnetlink_queue가 필요합니다. OpenWrt 기본 이미지에는 없습니다(`kmod-nft-queue kmod-nfnetlink-queue`). agent는 `nft -c`(커널까지 확인하되 적용하지 않음)로 미리 확인해 5분간 캐시합니다. 지원하지 않으면 경고 `nfqueue_unsupported`를 보내고, 인터페이스를 `ips_allowed=false`로 보고하며, IPS 요청은 POLICY 단계에서 거부합니다.
- **Endpoint PC/서버**: forward보다 input/output hook이 중심입니다. Docker 호스트라면 DOCKER 체인과 공존하도록 priority를 확인해야 합니다.

### 6.6 적용 파이프라인

```
DesiredState(gen) 수신
 ├─ 0. POLICY      인터페이스/IPS 허용 범위 검사
 ├─ 1. DOWNLOAD    bundle_id 가 로컬에 없으면 blob 스트림으로 수신 (offset 재개)
 ├─ 2. VERIFY      sha256 + manifest 서명(controller hostkey) + 압축 해제 크기 상한 + guard
 ├─ 3. RENDER      staging/{bundle}/ 에 풀고 ①②③ 병합 → effective yaml (인스턴스별)
 ├─ 4. VALIDATE    suricata -T -c effective.yaml (timeout, 출력 수집 → rule_errors 파싱)
 ├─ 5. FIREWALL    IPS 인터페이스 변경 시 Backend.Apply
 ├─ 6. ACTIVATE    current → releases/{bundle} 심링크 교체
 │                 · 룰만 변경   → unix-command `reload-rules` (무중단)
 │                 · yaml/모드 변경 → 인스턴스 restart
 ├─ 7. HEALTHCHECK unix-command 응답, ruleset-stats(실패 룰 수), 캡처 상태
 └─ 실패 시: 6 이전이면 FAILED(현 상태 유지), 6 이후면 이전 릴리스로 ROLLED_BACK
     각 단계마다 ApplyReport 전송 (성공/실패/단계/원인/상세)
```

- generation을 직렬로 처리합니다. 진행 중에 새 desired가 오면 현재 작업이 안전한 지점에 이르렀을 때 최신 것으로 넘어갑니다.
- `suricata -T`는 룰 전체를 메모리에 올리므로 저사양 라우터에서는 메모리가 순간적으로 치솟을 수 있습니다. agent 설정으로 동시성과 타임아웃을 조절합니다.

### 6.7 로그 수집 (agent 측)

- **로그 파일의 위치와 형식은 노드 사용자가 정합니다.** agent는 Suricata 출력을 추가하거나 바꾸지 않고, 사용자가 만든 파일을 읽기만 합니다. 그래서 Elastic Agent, Filebeat, Vector 같은 외부 수집기가 같은 파일을 함께 읽을 수 있습니다.
  - 인스턴스별 로그 디렉터리(`suricata.instances.*.log_dir`)는 agent.yaml에서 정하고, runtime 레이어 ③에서 `default-log-dir`로 강제합니다. ids와 ips 두 인스턴스가 같은 파일에 쓰지 않게 하기 위해서입니다. 사용자 설정의 상대 경로 파일명은 이 디렉터리 아래에 만들어집니다.
  - docker에서는 이 디렉터리를 호스트 경로로 bind mount하면 호스트의 외부 수집기가 읽을 수 있습니다.
- **수집 대상 자동 탐지**: 인스턴스마다 effective config를 보고 읽을 파일을 찾습니다.
  - `outputs[].eve-log`(filetype `regular`/`file`): `filename` → `eve`. 켜져 있는 `types`도 함께 기록합니다.
  - `outputs[].fast`, `outputs[].stats` → `fast`, `stats`
  - `logging.outputs[].file.filename` → `suricata.log`. 파일 출력이 없으면 supervisor가 받은 stdout/stderr를 씁니다.
  - eve `types`의 `files`는 event_type `fileinfo`로 바꿔 기록합니다.
  - 수집하지 않는 타입의 파일은 읽지 않고 offset만 끝으로 옮깁니다. 라우터 CPU를 아끼기 위해서입니다.
  - 파일이 아닌 출력(redis, syslog, unix socket)은 건너뛰고 경고만 보고합니다.
  - `logs.extra_sources`로 탐지되지 않는 파일을 추가할 수 있습니다.
- **가용성 보고**: 탐지 결과(로그 타입, 파일 경로, eve에서 켜진 event_type)를 Hello/Status로 보냅니다. controller UI는 노드에서 실제로 수집 가능한 항목만 선택할 수 있게 표시합니다. 사용자 출력에 없는 event_type은 수집할 수 없습니다.
- **tail**: inode와 offset을 `state/` 아래에 저장하고, 재시작하면 이어서 읽습니다. 처음 발견한 파일은 `start_position`(기본 `end`)부터 읽습니다. rename/truncate rotation을 감지합니다(filebeat와 같은 방식).
- **로컬 rotation(선택)**: `logs.rotation.enabled`이면 agent가 크기 기준으로 rename하고 SIGHUP으로 reopen시킨 뒤 `keep`개만 남깁니다. 외부 logrotate나 Suricata `rotate-interval`을 쓰는 경우 끕니다. 라우터 플래시가 가득 차는 것을 막기 위해 기본값은 켜짐입니다.
- **경로**: tail → event_type 필터(수집 정책) → **ringqueue**(`queue_max_bytes`, drop-oldest) → shipper(256KiB 또는 1s 단위 배치, zstd) → `logs` 스트림
  - controller가 느리면 yamux flow control 때문에 shipper가 block되고, 그동안 링 큐가 오래된 것부터 버립니다. drop 수는 Status로 보고합니다.
  - 연결이 끊긴 동안에도 링 큐 용량만큼은 버퍼링합니다.
- **정책 변경**: 수집 정책은 읽을 파일과 필터만 바꾸므로 Suricata를 재시작하지 않고 즉시 반영됩니다.

### 6.8 상태 영속화

```
/var/lib/suri-agent/
  state.json               # applied generation, bundle, interface modes, log policy
  bundles/{id}.tar.zst     # 다운로드 캐시
  releases/{id}/           # 최근 N개 (로컬 롤백용)
  current -> releases/{id}
```

부팅하면 **controller 연결을 기다리지 않고** `state.json`과 `current`로 엔진을 기동하고 방화벽 규칙을 복원합니다.

### 6.9 Docker 배포

- 이미지는 **Alpine 3.24** 기반입니다. Suricata 8.0.7을 소스로 빌드하고(tarball SHA-256 고정, NFQ/AF_PACKET 포함), 같은 소스 트리로 suritap 캡처 플러그인(`/usr/lib/suricata/suritap.so`)을 빌드해 넣습니다. 여기에 `suri-node-agent`(static)와 `tini`가 들어갑니다. 플러그인은 정확히 같은 Suricata 빌드에만 로드되므로 패키지 대신 소스로 빌드합니다.
- 첫 실행에서 `/etc/suricata` 볼륨이 비어 있으면 패키지 기본 설정으로 채웁니다.
- multi-arch(amd64, arm64)로 빌드하고, `nft`/`iptables`는 fallback용으로 함께 넣습니다.

```yaml
services:
  suri-node-agent:
    image: ghcr.io/jc-lab/suri-node-agent:latest
    network_mode: host
    cap_add: [NET_ADMIN, NET_RAW, SYS_NICE]   # SYS_CHROOT 는 docker 기본 capability
    restart: unless-stopped
    volumes:
      - /:/host:ro                 # 호스트 도구 실행 (chroot /host nft …)
      - ./etc:/etc/suri-agent      # agent.yaml, agent_ed25519
      - ./suricata:/etc/suricata   # 사용자 base 설정, 로컬 룰
      - ./data:/var/lib/suri-agent # 상태/릴리스
      - /var/log/suricata:/var/log/suricata   # 로그 위치 (호스트의 Elastic Agent 등이 함께 읽을 수 있음)
      - /run/suritap:/run/suritap             # suritap 소켓 (tap.enabled, 프록시와 공유)
```

- 첫 실행: `docker run … suri-node-agent keygen --node-id router-01`을 실행하면 공개키 라인이 출력됩니다. 이 라인을 controller UI에 등록합니다. 등록되지 않은 키의 접속은 거부됩니다.
- `suri-node-agent check`: profile/probe 결과(OpenWRT, fw4, offload, 엔진 기능), 설정 검증, controller 연결 테스트를 출력합니다.
- OpenWRT에서는 `dockerd` 패키지가 필요하고, 충분한 저장 공간(USB/eMMC)이 있는 x86/arm64 기기를 권장합니다.

---

## 7. 보안 고려사항 요약

| 위협 | 대응 |
|---|---|
| TLS 종단 지점(cloudflared 등)에서 도청/변조 | Noise IK E2E, 양방향 static key 인증 |
| 가짜 controller | agent가 hostkey를 pin하고 번들 manifest 서명을 검증 |
| 미등록 노드 | 관리자가 사전 등록한 키만 허용, 그 외 즉시 거부 |
| handshake replay로 세션 끊기 | msg1에서 상태 변경 금지, 새 세션이 입증된 뒤 교체, timestamp 검사 |
| controller 탈취 → 노드 장악 | agent 로컬 정책(인터페이스/IPS), yaml guard, Lua 차단, 원격 명령 실행 기능 자체를 두지 않음 |
| guard 우회(점 표기 키 `plugins.0`, `security: {lua.allow-rules}`, `run_as` 같은 `_` 표기, YAML anchor) | overlay의 모든 깊이에서 `.` 포함 키와 anchor/alias 거부. `_`→`-` 정규화 후 금지 키 검사. agent runtime 키는 effective 문서의 맨 끝에 배치 |
| 번들로 임의 파일(예: 플러그인 .so) 전달 | 번들 경로 allowlist(`rules/suricata.rules`, `rules/{classification,reference,threshold}.*`, `rules/datasets/<md5>`, `config/controller.yaml`). 번들 ID는 hex sha256만 허용(경로 조작 차단) |
| 경로 조작 | node-id 정규식, git 경로 정규화, 번들 tar 경로 검증(zip-slip) |
| 압축 폭탄/대용량 | 번들(엔트리 수/크기 사전 검사, 중복 거부), 배치, 메시지 크기 상한. 관리 API 요청 크기 제한(인증 API 16KiB) |
| IPS 장애로 인한 네트워크 단절 | NFQUEUE bypass(fail-open), 실패 시 롤백 |
| 관리자 계정 공격 | bcrypt, rate limit(IPv6는 /64 단위, 프록시 헤더는 신뢰 시 가장 오른쪽 hop), 보안 쿠키, Authorizer 훅. 세션은 stateless HMAC 쿠키라 개별 폐기가 안 됨(만료 12h, 비밀키 교체로 전체 폐기) |

---

## 8. 구현 계획

각 Phase는 끝날 때 **동작하는 데모와 테스트**가 있어야 합니다.

### Phase 0. 기반
- go.mod, 디렉터리 골격, Makefile/Taskfile, golangci-lint(depguard로 패키지 경계 강제), GitHub Actions(lint/test/build)
- buf 설정, `agent/v1`, `api/v1` proto 초안, Go/TS 코드 생성
- `pkg/sshkey`: keygen, OpenSSH 포맷 입출력, fingerprint, ed25519→x25519. 변환 결과는 age(agessh)와 교차 검증합니다.
- **완료 조건**: CI green, `suri-node-agent keygen/pubkey` 동작

### Phase 1. 보안 전송 계층
- `pkg/noisews`: coder/websocket + flynn/noise IK, net.Conn 어댑터(분할/재조립), timestamp/replay 검사
- `pkg/wire`: yamux 세션, uvarint codec, Envelope RPC(요청/응답/notification, timeout)
- controller `agentgw`(WS endpoint, 세션 레지스트리), agent `conn`(재연결, 헤더, proxy)
- 노드 키 등록(임시로 메모리 store), 미등록 키 거부, Hello/Status
- **테스트**: 잘못된 hostkey, 미등록 키, replay, 대용량 메시지, 연결 끊김/재연결, HTTP/1.1 리버스 프록시 경유
- **완료 조건**: TLS 종단 리버스 프록시(httptest)를 거쳐 agent가 접속하고 online으로 표시됨

### Phase 2. Controller 코어 + 웹 골격
- `store`(SQLite + migration), `auth`(Provider/PasswordLogin/Authorizer, StaticAdmin, SessionManager)
- `controller.New(Options)` 공개 API, `cmd/suri-controller`(설정 파일, env, flag)
- Connect `AuthService`, `NodeService`, `SystemService`
- web: 로그인, 노드 목록/상세, 공개키 등록, hostkey 표시
- **완료 조건**: UI에서 노드를 등록하고 상태를 확인함. 예제 프로그램에서 controller를 embed해 동작 확인

### Phase 3. Git 저장소 & 룰 소스
- `gitrepo`: bare repo 초기화, TreeBuilder 커밋(CAS), log, diff, 특정 commit의 파일 읽기, repack
- `rules`: Provider 인터페이스, et-open(md5 확인, 다운로드, 압축 해제, 변경 시에만 커밋), local, 스케줄러
- `RuleService`: provider 설정, SyncNow, 커밋/diff, local 룰 편집
- web: 룰 페이지(provider, 커밋 이력, diff, local 편집기)
- **완료 조건**: ET Open 주기 동기화 커밋이 쌓이고 UI에서 diff를 확인함

### Phase 4. 설정 저장소 & 렌더러 & 배포 정책
- `pkg/ruleset`: 파서, matcher(sid/gid:sid/re/group/metadata), disable→enable→drop→modify, flowbits 해석
  - **golden test**: ET Open과 샘플 conf 세트로 suricata-update 출력과 동일한지 확인
- `configrepo`: common + nodes/{id} 병합, `pkg/yamlmerge`
- `pkg/bundle` + `render`: 번들 생성, 서명, 캐시, Preview API
- `deploy`: 정책(auto/pinned/paused) × 2, effective commit 계산, desired state/generation, 연결된 노드에 push
- web: 설정 편집기(트리, 커밋, diff), 배포 정책 UI, 노드 미리보기
- **완료 조건**: 커밋을 pin해 롤백하면 노드별 desired가 바뀌는 것을 확인함(agent는 아직 mock)

### Phase 5. Agent 적용 파이프라인 + IDS/IPS
- `platform`: Profile(docker), HostExec(chroot, fallback), HostFS, Probe(OpenWRT/fw4/offload)
- `engine/supervisor`: 인스턴스 시작/정지/재시작, stdout 캡처, `--build-info` 파싱. `engine/unixsock`: reload-rules, ruleset-stats, iface-stat, dump-counters
- `reconcile`: 6.6의 파이프라인, releases/롤백, ApplyReport, state 영속화, 오프라인 부팅
- 6.4 레이어링, shadowed keys, guard, Lua 정책
- `firewall`: nftables 먼저, 그다음 iptables. `Check` 기반 재적용, 종료 시 정리
- 인스턴스 계획(ids/ips/혼합), 인터페이스 정책 검증
- Docker 이미지(multi-arch), compose, `check` 명령
- web: 인터페이스 모드 선택, 적용 이력과 실패 상세(rule_errors)
- **완료 조건**: netns/veth 테스트베드에서 IDS alert와 IPS drop을 확인함. 잘못된 룰을 배포하면 FAILED가 보고되고 기존 룰이 유지됨

### Phase 6. 로그 수집
- `pkg/ringqueue`(byte 상한, drop-oldest, 통계)
- agent `collector`: effective config 기반 수집 대상 탐지, tail(inode/offset 영속화, rotation 감지), 선택적 로컬 rotation, process output source, event_type 필터, shipper(zstd 배치)
- controller `logs`: ingest 큐, 수집 정책(global/node), FileSink(segment, zstd), retention janitor
- `LogService` + web: 정책 행렬(전체/노드별 선택), 로그 브라우저(tail/다운로드), retention 설정, 큐/드롭 통계
- **완료 조건**: 부하 테스트에서 큐가 가득 차면 오래된 것부터 버리는지, retention이 삭제를 정상 수행하는지 확인함

### Phase 7. 마무리 & 하드닝
- 대시보드, 감사 로그, Hooks(이벤트 콜백)
- E2E: docker compose(controller + agent 2대 + netns 라우터 시뮬레이션 + tcpreplay)
- 보안 점검(fuzz: proto/tar/rule 파서, `go test -fuzz`), 문서(설치, OpenWRT 가이드, embed 가이드)
- 릴리스 파이프라인(goreleaser, ghcr 이미지)

### Phase 8. 향후
- native OpenWRT profile(`procd` Runtime, fw4, opkg 패키지 / apk), systemd profile
- 노드별 pin(canary), 단계적 rollout
- git smart-HTTP(GitOps), 외부 remote mirror
- 추가 Rule Provider(URL, ET Pro 등), 외부 LogSink(ES/Loki), alert 검색/대시보드
- agent 키 rotation, 다중 관리자/RBAC(Authorizer 활용)

---

## 8.1 구현 현황 (2026-10-14)

| Phase | 상태 | 비고 |
|---|---|---|
| 0 기반 | 완료 | go.mod, proto/생성, Makefile, CI, golangci-lint(depguard로 패키지 경계 강제) |
| 1 보안 전송 | 완료 | noiseconn(IK), wire(yamux, RPC), agentgw, agent/conn. TLS 종단 프록시 경유 테스트 포함 |
| 2 Controller 코어 | 완료 | SQLite store, auth(StaticAdmin + CookieSession, CSRF/rate limit), Connect API, `controller.New` |
| 3 Git & 룰 소스 | 완료 | gitrepo(worktree 없는 TreeBuilder, CAS, repack, `git fsck` 검증), ET Open/URL/local provider, 스케줄러 |
| 4 설정 & 렌더러 & 배포 | 완료 | configrepo 레이어링, ruleset(suricata-update 동등성), bundle(서명), deploy(auto/pinned/paused) |
| 5 Agent 적용 + IDS/IPS | 완료 | reconcile(롤백, 재부팅 복원, 로컬 변경 감지), supervisor, nftables/iptables, Docker 이미지 |
| 6 로그 수집 | 완료 | collector(탐지, tail, rotation, 필터), ringqueue, FileSink(rotation/압축/retention), tail 스트리밍 |
| 7 웹 UI | 완료 | `web/ui` (React + Mantine + Connect, hash 라우팅, CSP 적용). 생성된 TS(`web/ui/src/gen`)는 커밋 대상 |
| 8 향후 | — | procd/systemd runtime, 노드별 pin(canary), GitOps, 외부 LogSink, 키 rotation, RBAC |

검증 현황:
- 단위 테스트, controller/agent 통합 테스트(`test/`), 로컬 `suricata -T` 검증 테스트를 모두 갖췄습니다.
- `test/docker/integration.sh`는 실제 Suricata 8.0.7로 다음을 확인합니다.
  - IDS 경보 수집
  - IPS(NFQUEUE) 차단
  - `-T` 실패 시 기존 설정 유지
  - pin 롤백
  - controller 없이 재부팅했을 때 IPS 복원

### 8.2 suritap (TLS 종단 프록시 평문 검사)

TLS 종단 프록시가 평문을 공유메모리(또는 UNIX 스트림 소켓)로 Suricata capture plugin에 넘기고 판정을 받는 확장입니다.

| 단계 | 상태 | 내용 |
|---|---|---|
| 1 | 완료 | Rust 플러그인, Go/Rust 클라이언트, 실제 Suricata 8.0.7 검증 스크립트 |
| 2 | 완료 | Traefik 플러그인(Yaegi, 소켓 전송)과 패치 빌드(공유메모리, HTTP transaction tap, TLS 종단 TCP stream tap, v3.7.14 패치) |
| 3 | 완료 | Kong 플러그인(Lua, 소켓 전송을 cosocket으로, 응답 prevent는 짝 플러그인 `suritap-response`) |
| 5 | 완료 | 이 컨트롤러와 통합: agent의 `tap` 인스턴스, 엔드포인트별 Off/Detect/Prevent(controller → agent 정책 파일 → 플러그인 POLICY → 어댑터), 소스 빌드 Suricata + 플러그인 이미지 |

설계, 명세, 검증 결과는 [suritap.md](suritap.md)를 참고하세요.

## 9. 테스트 전략

| 레벨 | 대상 | 방법 |
|---|---|---|
| Unit | sshkey, noisews, wire, ringqueue, yamlmerge, bundle | table test, fuzz |
| Golden | `pkg/ruleset` | ET Open 스냅샷 × conf 세트를 suricata-update 출력과 diff |
| Integration | agent engine/firewall | docker 안에서 실제 Suricata, netns + veth, pcap/tcpreplay로 alert/drop 확인 |
| Integration | controller gitrepo/render/deploy | 임시 data dir, fake provider(로컬 tar.gz) |
| E2E | 전체 | compose: controller + agent×2, 배포 → 적용 → 롤백 → 로그 수집 시나리오 |
| 호환성 | 전송 | TLS 종단 리버스 프록시(httptest, nginx) 경유 |

---

## 10. 리스크 & 미결정 사항

| 항목 | 내용 / 제안 |
|---|---|
| 모듈 경로 | `github.com/jc-lab/suricontroller` (확정) |
| IDS+IPS 혼합 | 인스턴스 2개 허용 (확정). 메모리 약 2배 |
| Suricata 기준 버전 | 8.0.5 이상 (확정). ET Open 기본 경로는 `suricata-8.0.5` |
| config.git 노드 경로 | `nodes/{node-id}/` (확정) |
| suricata-update 동등성 | flowbits, metadata matcher 등 세부 동작 차이가 생길 수 있음 → golden test로 관리 |
| rules.git 용량 | 매일 커밋되는 ET 룰 → repack 필수. 장기적으로 오래된 commit을 정리하는 정책(pinned 제외) 검토 |
| 로그 위치 | 노드 사용자가 정함 (확정). agent는 파일을 읽기만 함. 사용자 출력에 없는 event_type은 수집 불가 |
| 미등록 노드 | 즉시 거부 (확정) |
| 저사양 라우터 | `suricata -T` 메모리 스파이크, 룰셋 크기 → `sources.yaml`과 disable.conf로 노드별 룰 축소 권장 |
| flow offloading | 감지와 경고만 함. 자동 비활성화 옵션 제공 여부 결정 필요 |
| 로그 저장 | 현재는 파일 저장과 조회만. alert 검색이 필요하면 SQLite/외부 sink 인덱싱 추가 |
