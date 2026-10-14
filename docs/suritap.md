# suritap — TLS 종단 프록시 평문의 Suricata 검사

TLS를 종단하는 프록시(Traefik, Kong 등)가 복호화한 평문을 공유메모리로 Suricata에 넘기고, 요청 단위 판정(pass/drop)을 돌려받는 구성 요소다. 이 문서는 1단계(전송·플러그인·클라이언트)와 2단계(Traefik 어댑터)의 설계, 프로토콜 명세, 검증 결과를 다룬다.

## 1. 구성 요소

| 경로 | 언어 | 역할 | 라이선스 |
|---|---|---|---|
| `tap/suritap` | Rust | 프로토콜·공유메모리 링·패킷 합성 엔진·서버 워커·**Rust 클라이언트**(libsuritap 역할), `suritap-mockd` | MPL-2.0 |
| `tap/suritap-plugin` | Rust (+ 얇은 C glue) | Suricata 8 capture plugin `suritap.so` | GPL-2.0-only |
| `pkg/suritap` | Go | **Go 클라이언트**(libsuritap 역할) | MPL-2.0 |
| `adapters/traefik` | Go | Traefik 어댑터(`suritaptraefik`). Traefik에 의존하지 않는 net/http 미들웨어와 TCP 래퍼 | MPL-2.0 |
| `deploy/traefik` | patch / sh | Traefik v3.7.14 연결 패치와 빌드 스크립트 | — |
| `cmd/suritap-probe` | Go | 기능 검증(`check`), 벤치마크(`bench`, `httpbench`), 크래시 테스트(`hold`), 테스트 백엔드(`backend`) | MPL-2.0 |
| `test/tap` | sh / yaml | 실제 Suricata로 검증: 1단계 `run.sh`, Traefik `traefik.sh`, 테스트 룰·설정 | — |

Suricata 코드에 링크되는 것은 `suritap.so`뿐이다. 프록시는 공유메모리와 UNIX 소켓 너머에 있으므로 GPL과 무관하다.

## 2. 아키텍처

```
Client ──TLS──▶ [Proxy + suritap client] ──plain──▶ Upstream
                    │  memfd (sealed): c2s ring ──▶   ◀── s2c ring
                    │  eventfd ×2 (잠든 쪽만 깨움), UDS(SEQPACKET): 핸드셰이크·생존 확인
                    ▼
        [suricata --capture-plugin=suritap]   워커 스레드마다 worker-N.sock
          receive(Rust) → decode → FlowWorker(stream inline, app-layer, detect, output)
            ├─ release 콜백 → VERDICT(action, reason, alerts)
            ├─ flow update 콜백 → BYPASS
            └─ EVE 콜백 → "suritap": {cid, session, client, sni, ...}
```

- 클라이언트는 Suricata 워커마다 세션을 하나씩 열고, 연결 ID(cid) 해시로 세션을 고른다. 그래서 한 연결의 패킷은 항상 같은 워커가 처리한다. workers 런모드에서는 수신, 탐지, 판정이 한 스레드 안에서 이뤄지고 큐를 거치지 않는다.
- Suricata는 IPS 모드로 동작한다(`stream.inline`). 데이터는 패킷이 처리되는 즉시 검사되므로 ACK flush 패킷이 필요 없다.
- 워커 스레드는 `receive → decode → FlowWorker`만으로 구성한다. `RespondReject`는 넣지 않는다. 주입할 실제 회선이 없으므로 reject 룰은 판정에서 drop으로 보고되고, RST나 403을 보낼지는 어댑터가 결정한다.

## 3. 공유메모리 전송

### 3.1 Region (클라이언트가 생성)

`memfd_create(MFD_ALLOW_SEALING)`로 만들고 `F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_SEAL`을 건다. 서버는 seal을 확인한 뒤에만 매핑한다. 클라이언트가 파일을 잘라 Suricata에 SIGBUS를 일으키는 것을 막기 위해서다. 모든 정수는 little-endian이다.

| 오프셋 | 내용 |
|---|---|
| 0 | `u32 magic "STAP"`, `u16 version=1`, `u16 header=4096`, `u32 flags`, `u64 region size`, `u64 c2s off/size`, `u64 s2c off/size` |
| 1024 | c2s 링 제어(64바이트 라인별 `head`, `tail`, `consumer_waiting`, `producer_waiting`) |
| 2048 | s2c 링 제어 |
| 4096 | c2s 링 데이터(2의 거듭제곱, 64 KiB ~ 1 GiB) |
| 4096+c2s | s2c 링 데이터 |

서버는 헤더를 한 번만 읽어 검증하고, 이후 레이아웃 값을 다시 읽지 않는다(TOCTOU 방지). 링 인덱스는 0에서 시작해야 한다. 크기 상한은 `suritap.max-region-size`로 정한다.

### 3.2 SPSC 링

- 레코드는 8바이트 정렬이며 `len:u32 | kind:u16 | flags:u16 | body` 형식이다. 레코드는 링 끝에서 넘어가지 않는다. 남은 공간이 부족하면 PAD 레코드로 채운다. 최대 레코드 크기는 링의 1/4이다.
- `head`와 `tail`은 바이트 단위로 계속 증가하는 카운터다.
- 깨우기 규칙은 다음과 같다. 시스템콜은 상대가 잠들어 있을 때만 발생한다.
  - 소비자는 잠들기 전에 `consumer_waiting=1`로 표시하고 `head`를 다시 확인한다.
  - 생산자는 `head`를 publish한 뒤 플래그를 0으로 swap하고, 원래 값이 1이었을 때만 eventfd를 쓴다.
  - 두 연산은 Rust에서 SeqCst, Go에서 sync/atomic으로 처리하므로 깨우기 신호가 유실되지 않는다.
  - 링이 가득 찼을 때도 `producer_waiting`으로 같은 규칙을 적용한다.
- 소비자는 상대를 신뢰하지 않는다. 모든 길이를 링 경계와 비교해 검증하고, 바이트는 복사해서만 꺼낸다. 형식을 위반하면 세션을 닫는다.

### 3.3 핸드셰이크 (`SOCK_SEQPACKET`)

| 메시지 | 내용 | SCM_RIGHTS |
|---|---|---|
| HELLO (64B) | magic, version, pid, flags, client name[32] | memfd |
| WELCOME (64B) | status, worker_index, worker_count, max_payload, max_flows, session_id, message | 성공 시 eventfd 2개(c2s, s2c). 서버가 만든다 |

eventfd는 서버가 생성하므로 서버가 그 유형을 신뢰할 수 있다. 핸드셰이크 뒤에는 소켓으로 아무것도 보내지 않으며, 소켓 종료(HUP)가 곧 세션 종료다. 클라이언트가 죽으면 서버는 그 세션의 열린 flow를 RST로 정리한다.

연결 후 2초 안에 HELLO를 보내지 않으면 서버가 연결을 끊는다. 대기 중인 연결이 64개를 넘으면 가장 오래 기다린 연결부터 끊는다. 아무것도 보내지 않는 연결이 정상 클라이언트를 막지 못하게 하기 위해서다. 링 커서는 공유메모리에서 다시 읽지 않고 항상 0에서 시작한다(검증 후 변경 방지).

### 3.4 레코드

| 방향 | kind | body |
|---|---|---|
| c2s | `OPEN=1` | `cid:u64 family:u8(4/6) hint:u8 rsv:u16 tenant:u32 sport:u16 dport:u16 rsv:u32 src[16] dst[16]` + TLV(`tag:u8 rsv:u8 len:u16 value`, 합계 ≤2048) |
| c2s | `DATA=2` | `cid:u64 dir:u8 rsv[3] token:u32` + payload. flag `WANT_VERDICT=1` |
| c2s | `GAP=3` / `EOF=4` / `CLOSE=5` | `cid:u64 dir|how:u8 rsv[3] len:u32` (CLOSE how: 0 FIN, 1 RST) |
| c2s | `PING=6` | `token:u32 rsv:u32 ts:u64` |
| s2c | `VERDICT=0x81` | `cid:u64 token:u32 dir:u8 action:u8 reason:u8 n:u8 drop_reason:u8 rsv[3] alert_total:u16 rsv:u16` + n×`(sid gid rev:u32 action:u8 rsv[3])` (n≤8) |
| s2c | `BYPASS=0x82` | `cid:u64 dir:u8 rsv[7]` |
| s2c | `PONG=0x83` | PING 그대로 |
| s2c | `FLOW_ERROR=0x84` | `cid:u64 code:u32` (1 중복 cid, 2 flow 한도 초과, 3 잘못된 OPEN) |

메타 태그 번호: 1 sni, 2 alpn, 3 ja4, 4 route, 5 request_id, 6 endpoint, 7 service, 8 user, 9 proto, 10 proxy. 알 수 없는 태그는 버리고, 같은 태그가 여러 번 오면 첫 값만 쓴다.

### 3.5 판정 의미

- `WANT_VERDICT`가 붙은 DATA에는 그 방향으로 지금까지 보낸 모든 데이터를 덮는 판정이 온다. 이전 레코드의 drop과 alert도 누적되어 함께 보고된다.
- 한 번이라도 drop된 연결은 이후 모든 판정이 drop(`reason=flow`)이다. 방향과 무관하며, 페이로드 없는 판정 요청에도 적용된다(fail-closed).
- `action`
  - `pass`: 통과.
  - `drop`: 차단. drop·reject 룰이나 엔진 정책에 걸린 경우다.
  - `error`: 판정을 낼 수 없음. 어댑터의 fail-open/fail-closed 정책을 적용한다.
- `reason`
  - `rule`: drop·reject 룰이 매치됐다.
  - `policy`: exception policy, memcap, stream·decoder·app-layer 오류.
  - `flow`: 이전 판정으로 이미 drop된 flow다.
  - `unknown-flow`: 알 수 없는 cid.
  - `protocol`: 잘못된 레코드.
  - `engine`: 엔진이 패킷을 처리하지 못했다.

  `drop_reason`은 Suricata의 `PKT_DROP_REASON_*` 원값이다(버전마다 다르다).
- alert는 pass 판정에도 실린다. 예를 들어 alert 전용 룰이 매치된 경우다. `action` 비트는 alert=1, drop=2, reject=4/8/16이다.
- 크레딧: 클라이언트가 동시에 기다릴 수 있는 판정 수는 `s2c 크기 / 최대 VERDICT 레코드 / 2`로 제한한다. 그래서 서버는 s2c가 가득 차서 막히는 일이 없다. 이를 어기면 프로토콜 위반으로 세션을 닫는다.
- 크레딧 없이 오는 레코드(BYPASS, FLOW_ERROR)는 s2c의 절반이 비어 있을 때만 보낸다. 그렇지 않으면 버린다. 그래서 이런 레코드가 쌓여도 판정 레코드는 항상 들어간다.

## 4. 패킷 합성 (`tap/suritap/src/engine.rs`)

- **연결 수립**: OPEN을 받으면 실제 클라이언트 주소와 리스너 주소 사이에 IPv4 또는 IPv6 3-way handshake를 합성한다. SYN에는 MSS 65495와 WS 14 옵션을 넣는다.
- **데이터**: DATA는 `max-segment`(기본 32 KiB) 이하의 PSH|ACK 세그먼트로 나눈다. seq는 ISN과 오프셋으로, ack는 상대 방향 누적값으로 계산한다.
- **ACK 보충**: 한 방향의 미확인 바이트가 `ack-threshold`를 넘으면 상대 쪽에서 pure ACK를 넣는다.
- **종료와 GAP**: EOF는 FIN과 상대 ACK로, CLOSE는 FIN 양방향 또는 RST로 바꾼다. GAP은 seq를 건너뛰고 상대 ACK를 넣어 엔진이 gap으로 인식하게 한다.
- **연결 구분자**: 연결마다 (session, cid)에서 파생한 VLAN id 2개(각 1..4094, 약 24비트)를 붙인다. 자세한 이유는 §7.1을 본다. 필요 조건은 `vlan.use-for-tracking: true`(기본값)이고, EVE에 `vlan`이 표시된다.
- **keepalive**: `keepalive` 이상 유휴인 연결에는 pure ACK를 넣는다. 기본값은 `flow-timeouts.tcp.established / 3`이다. 오래 유휴인 연결(풀링된 DB 클라이언트, websocket)을 엔진이 timeout시킨 뒤 midstream으로 오탐 drop하는 것을 막는다.
- **메모리**: 패킷 버퍼는 워커당 하나를 재사용한다(256B headroom + 최대 패킷). 페이로드는 링에서 이 버퍼로 한 번만 복사하고, Suricata에는 `PacketSetData`로 zero-copy로 넘긴다. 그 뒤 링 공간은 즉시 반환되므로 링은 처리 중인 버스트만큼만 있으면 된다. flow 상태는 연결당 약 150B이고, alert 누적 버퍼는 alert가 생길 때만 할당한다.
- **체크섬**: TCP 체크섬은 계산하지 않고(`PKT_IGNORE_CHECKSUM`), IPv4 헤더 체크섬만 계산한다. `suritap-mockd --pcap`은 체크섬을 채운 pcap을 쓰므로 일반 Suricata로 재생할 수 있다.

## 5. Suricata 플러그인

### 5.1 빌드와 실행

```sh
# 플러그인은 로드될 Suricata와 같은 버전·같은 configure의 소스 트리로 빌드해야 한다.
make tap SURICATA_SRC=/path/to/suricata-8.0.7   # tap/target/release/libsuritap_plugin.so
suricata -c suricata.yaml --capture-plugin=suritap
```

- 빌드할 때의 버전(`PACKAGE_VERSION`)과 로드한 Suricata 버전이 다르면 등록을 거부한다. C glue가 `Packet` 등의 구조체 레이아웃에 의존하기 때문이다.
- C glue(`shim/shim.c`)는 Rust FFI로 호출할 수 없는 static inline 함수(`TmThreadsSlotProcessPkt` 등), 매크로, 구조체 필드 접근을 감싸기만 한다. 로직은 모두 Rust에 있다.
- 플러그인 통계 카운터는 `suritap.sessions/records/packets/bytes/verdicts/drops/flows/errors/bypasses/keepalives`다.

### 5.2 설정 (`suritap:`)

| 키 | 기본값 | 설명 |
|---|---|---|
| `socket-dir` | `/run/suritap` | `worker-N.sock` 생성 위치. `--capture-plugin-args`로 덮어쓸 수 있다. 접근 제어는 디렉터리 권한으로 한다 |
| `socket-mode` | — | 소켓 chmod(8진수) |
| `threads` | `auto` | 워커 수 |
| `ips` | `yes` | IPS 모드(판정에 drop 포함). `no`면 IDS 모드라 drop 룰도 alert로만 동작한다 |
| `max-sessions` / `max-flows` / `max-worker-flows` | 256 / 65536 / 262144 | 워커당 세션 수 / 세션당 flow 수 / 워커 전체 flow 수 |
| `max-segment` / `ack-threshold` | 32kb / 32kb | 합성 세그먼트 크기 / pure ACK 기준(§7.5: HTTP 바디 minimal inspect size의 3배보다 충분히 작게) |
| `max-region-size` | 64mb | 받아들이는 region 상한 |
| `batch` / `spin-us` / `idle-ms` | 64 / 0 / 100 | 세션당 한 번에 처리할 레코드 수 / 잠들기 전 busy-poll 시간 / 유휴 주기 |
| `discriminator` / `keepalive` | `yes` / `auto` | §4 참고 |

### 5.3 tap 인스턴스 권장 Suricata 설정

| 설정 | 권장값 | 이유 |
|---|---|---|
| `stream.reassembly.depth` | `0` | 프록시는 한 연결로 요청을 많이 보낸다(keepalive, h2). depth 1mb에서는 누적 1 MB 이후의 요청이 검사되지 않는다(§7.3) |
| `stream.bypass` | `no` | 위와 같은 이유. bypass는 `bypass` 키워드 룰에만 쓴다 |
| `HOME_NET` | 프록시 리스너 주소만 | 내부 클라이언트도 EXTERNAL이 되어 인바운드 웹 룰이 적용된다 |
| `HTTP_PORTS` | `[80,443,8080,8443]` | 평문이 TLS 리스너 포트로 들어온다 |
| `request-body-minimal-inspect-size` | 낮게(예: 4kb~32kb) | 바디 룰은 이 크기만큼 쌓이거나 요청이 끝날 때 판정된다(§7.2) |
| libnet | 포함해서 빌드 | libnet이 없으면 `reject` 룰이 로드되지 않는다. 있으면 drop으로 보고된다 |
| `exception-policy` | 명시적으로 설정 | 정책 drop은 `reason=policy`로 구분되므로 어댑터가 fail-open/fail-closed를 정할 수 있다 |

예시: `test/tap/suricata-tap.yaml.in`.

## 6. 클라이언트

```go
c, err := suritap.Dial("/run/suritap", suritap.Options{Name: "traefik"})
conn, err := c.Open(suritap.OpenParams{Src: clientAddr, Dst: listenerAddr,
    Meta: []suritap.Meta{{Tag: suritap.MetaSNI, Value: sni}}})
v, err := conn.Inspect(ctx, suritap.ToServer, req)  // 판정 대기(Prevent)
err = conn.Send(ctx, suritap.ToClient, resp)        // 판정 없이(Detect)
conn.Close(false)
```

```rust
let client = Client::connect("/run/suritap", ClientOptions::default())?;
let conn = client.open(&OpenParams::new(src, dst).meta(MetaTag::Sni, "api.example.com"))?;
let v = conn.inspect(Dir::ToServer, req, Duration::from_millis(50))?;
```

- 큰 버퍼는 `max_payload` 단위로 나눠 보낸다. 링이 가득 차면 ctx나 timeout 안에서 기다린다(역압).
- `Close`는 블록하지 않는다. 링이 가득 차 있으면 CLOSE를 큐에 넣었다가, 다음 레코드보다 먼저 또는 공간이 생기는 즉시 보낸다. Close를 호출하지 않고 버린 Conn도 Go는 `runtime.AddCleanup`, Rust는 `Drop`으로 닫는다.
- 클라이언트는 IPv4-mapped IPv6 주소(듀얼스택 리스너)를 IPv4로 바꿔서 보낸다.
- 서버가 사라지면 진행 중인 요청은 즉시 `ErrClosed` / `BrokenPipe`로 실패한다.
- `Options.Spin`(Go)은 판정을 읽는 쪽이 잠들기 전에 busy-poll하는 시간이다.

## 7. 1단계 검증 결과

검증 환경: Suricata 8.0.7(소스 빌드, libnet 포함), x86_64 16코어. 재현 명령:

```sh
SURICATA_PREFIX=... SURICATA_SRC=... test/tap/run.sh [--bench]   # → ALL PASSED
```

| 항목 | 결과 |
|---|---|
| IPv4/IPv6 HTTP pass·drop, alert 전용 룰, 응답 방향 drop, raw stream 룰 | 통과 |
| HTTP/2 prior knowledge(h2c 프레임)에 `http.uri` drop | 통과. stream tap으로 h2를 그대로 넘겨도 http 키워드가 적용된다 |
| pgsql `pgsql.query` drop(StartupMessage → Query) | 통과 |
| reject 룰 | drop 판정(alert action 0x7). RST 주입은 시도하지 않는다 |
| drop 이후 같은 연결 | `reason=flow`로 계속 drop |
| GAP 이후 데이터 | 오류 없이 판정 |
| keepalive 연결 200회 요청·응답 후 공격 | drop |
| `ruleset-reload-nonblocking`으로 룰 추가·삭제 | 재시작 없이 즉시 반영 |
| 클라이언트 `kill -9` | 세션 정리, 열린 flow 25개 RST 처리, Suricata 정상 동작 |
| 워커 유휴 중 flow timeout | 25/25 EVE flow 레코드(timeout) 생성 |
| EVE 보강 | 모든 alert에 `suritap.{cid, session, client, sni}` 포함 |
| exception policy(pgsql 파서 오류, drop-flow) | `reason=policy`, drop_reason=6 |
| ET Open 전체(52,636개 룰) 로드 상태 | 같은 시나리오 모두 통과. ET 2049400도 함께 alert |

### 7.1 발견: 같은 5-tuple을 재사용할 때 남아 있는 flow가 새 연결을 삼킨다

drop되거나 bypass된 flow는 FIN과 RST가 엔진에서 처리되지 않으므로 timeout 전까지 남는다. 같은 주소·포트로 새 연결이 오면 Suricata가 기존 flow를 재사용하므로 다음 문제가 생긴다.

- 이전 flow가 drop된 경우: 새 연결이 이유 없이 drop된다.
- 이전 flow가 bypass된 경우: 새 연결이 **검사 없이 통과**한다. 공격자가 소스 포트를 직접 정해서 이 동작으로 검사를 우회할 수 있다.

해결: §4의 연결 구분자(VLAN id)를 기본으로 켠다. 회귀 테스트 `tuple-reuse-after-drop`과 `tuple-reuse-after-bypass`로 고정했다.

### 7.2 바디 룰의 판정 시점

- 마커를 바디 앞쪽에 둔 96 KiB 바디를 4 KiB씩 보내면, `request-body-minimal-inspect-size`(32 KiB)에 이른 직후, 실측으로는 32~36 KiB째 청크에서 drop된다.
- 마커가 마지막 청크에 있으면 요청이 끝나는 시점에 drop된다.

따라서 업스트림으로 아무것도 보내지 않고 막아야 하는 엔드포인트는 요청을 버퍼링한 뒤 완료 시점에 판정해야 한다. nginx나 Kong의 기본 동작이 이와 같다. 그렇지 않으면 inspect-size를 낮춘다.

### 7.3 발견: reassembly depth와 bypass는 연결 전체를 기준으로 한다

`stream.bypass: yes` + depth 1mb 설정에서는 keepalive 연결의 누적 트래픽이 1 MB를 넘는 순간 flow 전체가 bypass된다. 이후 요청은 검사 없이 약 2µs 만에 pass된다. tap 인스턴스는 depth 0, bypass no로 두고(§5.3), HTTP는 body limit으로 제어한다.

inline 모드는 검사가 끝난 세그먼트를 ACK와 무관하게 정리한다. reassembly memcap 4 MB에서 무확인 데이터 64 MB를 보내도 memcap 초과가 없었다.

### 7.4 성능 (워커 4개, 요청 약 512B와 응답 1 KiB 한 쌍 기준)

| 측정 | p50 | p99 | 처리량 |
|---|---|---|---|
| 전송 왕복만(PING, 엔진 미경유) | 4.6µs (양쪽 spin 시 2.4µs) | 22~35µs | — |
| 소규모 룰(8개), 단일 연결 | 37µs | 68µs | 25.7k 쌍/s |
| 소규모 룰, 64 연결 | 0.72ms(포화 큐잉) | 1.0ms | 74.8k 쌍/s |
| ET Open 전체, 단일 연결 | 111~131µs | 176~188µs | 7.4~8.4k 쌍/s |
| ET Open 전체, 64 연결 | 2.0ms(포화) | 2.8ms | 29.2k 쌍/s (워커 4개 모두 CPU 100%) |

비교 대상으로 같은 6만 패킷을 일반 Suricata 오프라인 모드(`-r`, `--simulate-ips`, 단일 스레드)로 처리하면 쌍당 약 85µs(11.7k 쌍/s)다. 플러그인 경로에서 워커 1개를 포화시키면 9.7k 쌍/s로, 오프라인 처리량의 약 83%다.

정리하면 지연은 탐지 엔진 비용이 지배하고, 공유메모리 전송 비용은 수 µs 수준이다. 서버 `spin-us: 50`을 켜면 저부하일 때 깨우기 지연이 줄어든다.

### 7.5 발견: HTTP 바디 검사는 제때 오는 ACK가 필요하다

처음에는 ACK 기준을 256 KiB로 두었다. 이 설정에서는 업로드 바디의 앞쪽 약 60 KiB 이후에 있는 마커를 놓쳤다. 합성 패킷을 pcap으로 떠서 일반 Suricata 오프라인 모드로 돌려도 결과가 같았다.

원인은 Suricata의 `HtpBodyPrune`이다. 확인되지 않은 바디가 `3 × max(minimal-inspect-size, inspect-window)`(기본 96 KiB)를 넘으면, 검사되지 않은 부분을 그냥 버린다.

ACK 기준을 4~64 KiB로 낮추자, 300 KiB나 500 KiB 지점의 마커도 그 데이터를 실은 청크에서 바로 차단됐다. 그래서 기본값을 32 KiB로 바꿨다. 회귀 테스트는 `body-deep-marker`다.

## 8. Traefik 어댑터 (2단계)

### 8.1 구조

| 대상 | 방식 | 이유 |
|---|---|---|
| HTTP(1.1, h2, h3) | **transaction tap**: 엔트리포인트 핸들러 체인에서 요청마다 HTTP/1.1로 정규화하고, 요청 하나를 합성 flow 하나로 검사한다 | `http.Server`는 `*tls.Conn` 타입 단언으로 ALPN(h2)과 `r.TLS`를 처리한다. 그래서 TLS 연결을 감싸면 HTTP/2가 깨진다. 또 h2와 h3의 다중화 스트림은 하나의 HTTP/1.1 바이트 스트림으로 표현할 수 없다 |
| TLS를 종단하는 TCP 라우터 | **stream tap**: 복호화된 `net.Conn`을 감싸 모든 Read와 Write를 검사한다 | 프로토콜과 무관하다(pgsql, MQTT 등) |

어댑터는 Traefik을 import하지 않는다. Traefik 쪽은 패치(`deploy/traefik/traefik-v3.7.14.patch`, 4개 파일, 50여 줄)로 연결한다.

1. `static.EntryPoint`에 `Suritap *suritaptraefik.Config` 필드를 추가한다. 그래서 static 설정(파일, CLI, 환경 변수)으로 그대로 설정할 수 있다.
2. `newHTTPServer`에서 forwarded-headers 처리 직후, 라우팅 전에 `suritaptraefik.Middleware`를 끼운다. HTTP와 HTTPS 서버에 모두 적용되고, h3 서버도 같은 핸들러를 쓴다.
3. `tcp.Manager`에서 TLS를 종단하는 TCP 라우터의 핸들러를 `suritaptraefik.WrapConn`으로 감싼다.
4. 어댑터 로그를 Traefik zerolog로 보낸다(`pkg/server/suritap.go`).

```sh
make traefik            # deploy/traefik/build.sh → bin/traefik-suritap (v3.7.14-suritap)
```

빌드 스크립트는 지정한 태그를 받아 패치를 적용하고, 이 저장소를 `replace`로 연결해 빌드한다. 그 결과 Traefik의 `golang.org/x/*`와 `klauspost/compress`는 마이너 버전이 올라간다. 패치한 패키지의 Traefik 단위 테스트는 통과했다. 대시보드 정적 파일은 빌드하지 않는다.

### 8.2 설정 (`entryPoints.<name>.suritap`)

```yaml
entryPoints:
  websecure:
    address: ":443"
    suritap:
      socketDir: /run/suritap
      mode: prevent          # prevent | detect
      response: detect       # off | detect | prevent
      failPolicy: open       # open | closed
      timeout: 100ms
      maxRequestBody: 1048576
      maxResponseBuffer: 65536
```

| 키 | 기본값 | 설명 |
|---|---|---|
| `mode` | `prevent` | `prevent`: drop 판정이면 차단한다. `detect`: 판정을 기다리지 않는다 |
| `response` | `detect` | 응답 검사 방식. `prevent`면 `maxResponseBuffer`까지 버퍼링한 뒤 응답 전체를 판정한다 |
| `failPolicy` | `open` | Suricata가 없거나 timeout일 때 통과(`open`)할지 503(`closed`)을 줄지 |
| `timeout` | `100ms` | 판정 대기 시간 |
| `maxRequestBody` | 1 MiB | 이 크기 이하의 요청 바디는 버퍼링하고 판정한 뒤 업스트림으로 보낸다. 큰 바디는 업스트림이 읽는 동안 청크마다 판정한다 |
| `maxResponseBuffer` | 64 KiB | prevent 응답을 버퍼링할 최대 크기 |

### 8.3 동작

- **차단 응답:** 차단된 요청은 403과 함께 `X-Suritap-Cid`를 받는다. 이 값은 EVE의 `suritap.cid`와 같다. 이때 업스트림이 이미 설정한 헤더(Set-Cookie 등)는 버린다.
- **큰 요청 바디:** 업스트림이 읽는 동안 판정한다. 중간에 drop되면 업스트림 요청을 끊고 클라이언트에는 403을 준다.
- **응답 prevent:** 작은 응답은 끝까지 모아 한 번에 판정한다. chunked 응답이면 종료 청크까지 포함한다. Suricata는 메시지가 끝나야 작은 바디를 검사하기 때문이다. 큰 응답은 스트리밍 중에 drop이 나면 연결을 중단한다.
- **WebSocket 등 Upgrade:** 핸드셰이크 요청까지만 검사한다.
- **메타데이터:** SNI, ALPN, HTTP 버전, 엔트리포인트, `X-Request-Id`를 보낸다. TCP는 라우터 이름(`name@provider`)도 보낸다. 모두 EVE의 `suritap.*`에 남는다.
- **Suricata 쪽 설정:** 리스너 주소를 `HOME_NET`에 넣어야 인바운드 룰이 적용된다(§5.3).

### 8.4 검증 (`test/tap/traefik.sh`, Suricata 8.0.7 + Traefik 3.7.14-suritap)

| 항목 | 결과 |
|---|---|
| h2와 h1의 정상 요청 / URI 공격 | 200 / 403 |
| 작은 바디 공격(h2), 스트리밍 바디 공격(h1, 300 KiB 지점) | 403. 작은 바디 공격은 백엔드에 닿지 않는다 |
| reject 룰(User-Agent) | 403 |
| 응답 유출 룰: detect / prevent 엔트리포인트 | 200(EVE alert) / 403 |
| suritap이 없는 엔트리포인트 | 그대로 통과 |
| TLS 종단 TCP 라우터 | 정상 echo는 통과, 공격 바이트는 연결 종료 |
| EVE 메타데이터 | `proxy=traefik, endpoint, sni, alpn=h2, proto, route=echo@file` |
| Suricata 중지 시 | fail-open 엔트리포인트는 200, fail-closed는 503 |
| 차단 로그 | Traefik 로그에 `WRN suritap: blocked … sids=[…]` |

HTTP/3는 같은 핸들러를 거친다. 다만 이 환경의 curl이 h3를 지원하지 않아 E2E에서는 빠졌다.

### 8.5 오버헤드 (`--bench`, GET 요청과 짧은 응답, 16 클라이언트, 소규모 룰, 워커 2개)

모든 프로세스가 같은 호스트에서 CPU를 나눠 쓴 조건이다.

| | suritap 없음 | prevent (응답 detect) | prevent (응답 prevent) |
|---|---|---|---|
| HTTP/2 | 25.3k req/s, p50 0.59ms | 18.5k, p50 0.80ms | 20.2k, p50 0.75ms |
| HTTP/1.1 | 34.5k req/s, p50 0.42ms | 22.1k, p50 0.68ms | 21.4k, p50 0.71ms |

요청당 추가 지연은 약 0.2~0.3ms다. 요청마다 합성 flow를 열고 닫는 비용(패킷 약 9개)이 대부분이다.

## 9. 알려진 제약과 다음 단계

- 단일 IPS 인스턴스에서 Detect(shadow) 모드로 쓰면, 처음 would-drop이 난 뒤로는 그 연결이 더 검사되지 않는다(flow drop).
- drop된 flow는 RST가 처리되지 않으므로 `flow-timeouts.tcp.established` 동안 엔진 메모리에 남는다. 구분자 덕분에 정확성 문제는 없다.
- 소켓에 접근할 수 있는 프로세스는 신뢰 경계 안에 있다. 세션·flow·메타데이터 상한으로 자원 사용은 제한하지만, 접근 제어는 소켓 디렉터리 권한으로 해야 한다.
- 플러그인은 Suricata 내부 헤더에 의존하므로 Suricata 버전마다 다시 빌드해야 한다.
- multi-tenant(`tenant` 필드는 예약됨)는 아직 없다. 데이터 경로 배치 최적화도 남아 있다.
- Traefik 어댑터의 제약:
  - 요청마다 합성 flow를 쓰므로, 같은 연결의 여러 요청에 걸친 공격은 보지 못한다. HTTP/1 연결 단위로 flow를 재사용하면 오버헤드도 줄일 수 있다.
  - 미들웨어가 엔트리포인트 단계에 있어서 HTTP 라우터와 서비스 이름은 메타데이터에 없다.
  - 패치는 Traefik 버전마다 따로 유지해야 한다.
- 다음 단계:
  - 3단계: Kong 어댑터(Lua/OpenResty)
  - 5단계: suricontroller 통합(agent의 `tap` 인스턴스, 엔드포인트별 Off/Detect/Prevent, 이미지)
