# suritap — TLS 종단 프록시 평문의 Suricata 검사

TLS를 종단하는 프록시(Traefik, Kong 등)가 복호화한 평문을 Suricata에 넘기고, 요청 단위 판정(pass/drop)을 돌려받는 구성 요소다. 전송은 두 가지다. 기본은 공유메모리이고, 공유메모리를 쓸 수 없는 클라이언트(Traefik Yaegi 플러그인, OpenResty/Kong Lua)를 위해 UNIX 스트림 소켓 전송도 있다. 이 문서는 1단계(전송·플러그인·클라이언트), 2단계(Traefik 어댑터), 3단계(Kong 어댑터), 5단계(suricontroller 통합)의 설계, 프로토콜 명세, 검증 결과를 다룬다.

## 1. 구성 요소

| 경로 | 언어 | 역할 | 라이선스 |
|---|---|---|---|
| `tap/suritap` | Rust | 프로토콜·공유메모리 링·패킷 합성 엔진·서버 워커·**Rust 클라이언트**(libsuritap 역할), `suritap-mockd`. crates.io의 [`suritap`](https://crates.io/crates/suritap)로 배포한다(`v*` 태그 push 때 CI가 태그 버전으로 게시) | MPL-2.0 |
| `tap/suritap-plugin` | Rust (+ 얇은 C glue) | Suricata 8 capture plugin `suritap.so` | GPL-2.0-only |
| `pkg/suritap` | Go | **Go 클라이언트**(libsuritap 역할) | MPL-2.0 |
| `adapters/traefik-plugin` | Go (표준 라이브러리만) | **Traefik 플러그인**(Yaegi, 소켓 전송). 공식 Traefik 바이너리에 그대로 로드된다. HTTP 검사 로직은 패치 방식과 공유한다. 별도 저장소 [jc-lab/suritap-traefik](https://github.com/jc-lab/suritap-traefik)(모듈 `github.com/jc-lab/suritap-traefik`)의 submodule이다 | MPL-2.0 |
| `adapters/traefik` | Go | 패치 방식 Traefik 어댑터(`suritaptraefik`). 플러그인의 HTTP 로직을 공유메모리 클라이언트로 쓰고, TLS 종단 TCP 라우터용 래퍼를 더한다 | MPL-2.0 |
| `deploy/traefik` | patch / sh | 패치 방식용 Traefik v3.7.14 연결 패치와 빌드 스크립트 | — |
| `adapters/kong` | Lua (OpenResty) | **Kong 플러그인** `suritap`과 짝 플러그인 `suritap-response`, 순수 Lua 소켓 전송 클라이언트 | MPL-2.0 |
| `cmd/suritap-probe` | Go | 기능 검증(`check`), 벤치마크(`bench`, `httpbench`), 크래시 테스트(`hold`), 테스트 백엔드(`backend`) | MPL-2.0 |
| `test/tap` | sh / yaml / Go / Lua | 실제 Suricata로 검증: 1단계 `run.sh`, Traefik `traefik.sh`, Kong `kong.sh`, 테스트 룰·설정. `test/tap/yaegi`는 플러그인을 Traefik과 같은 방식으로 Yaegi에서 실행하는 하네스이고, `test/tap/kong/transport.sh`는 Kong 이미지의 OpenResty로 Lua 클라이언트를 검사한다 | — |

Suricata 코드에 링크되는 것은 `suritap.so`뿐이다. 프록시는 공유메모리와 UNIX 소켓 너머에 있으므로 GPL과 무관하다.

| 클라이언트 | 전송 |
|---|---|
| Go `pkg/suritap`, Rust `tap/suritap` | 공유메모리 |
| Traefik 플러그인(Yaegi) | 소켓. Yaegi는 `unsafe`/`syscall` 없이는 mmap·SCM_RIGHTS를 쓸 수 없다 |
| Traefik 패치 빌드 | 공유메모리 |
| Kong 플러그인(Lua) | 소켓(OpenResty cosocket). Lua에서는 memfd·eventfd를 다룰 수 없다 |

## 2. 아키텍처

```
Client ──TLS──▶ [Proxy + suritap client] ──plain──▶ Upstream
                    │  memfd (sealed): c2s ring ──▶   ◀── s2c ring
                    │  eventfd ×2 (잠든 쪽만 깨움), UDS(SEQPACKET): 핸드셰이크·생존 확인
                    ▼
        [suricata --capture-plugin=suritap]   워커 스레드마다 worker-N.sock(공유메모리)
          │                                     + worker-N.stream.sock(소켓 전송, §3.6)
          receive(Rust) → decode → FlowWorker(stream inline, app-layer, detect, output)
            ├─ release 콜백 → VERDICT(action, reason, alerts)
            ├─ flow update 콜백 → BYPASS
            └─ EVE 콜백 → "suritap": {cid, session, client, sni, ...}
```

- 클라이언트는 Suricata 워커마다 세션을 하나씩 열고, 연결 ID(cid) 해시로 세션을 고른다. 그래서 한 연결의 패킷은 항상 같은 워커가 처리한다. workers 런모드에서는 수신, 탐지, 판정이 한 스레드 안에서 이뤄지고 큐를 거치지 않는다.
- Suricata는 IPS 모드로 동작한다(`stream.inline`). 데이터는 패킷이 처리되는 즉시 검사되므로 ACK flush 패킷이 필요 없다.
- 워커 스레드는 `receive → decode → FlowWorker`만으로 구성한다. `RespondReject`는 넣지 않는다. 주입할 실제 회선이 없으므로 reject 룰은 판정에서 drop으로 보고되고, RST나 403을 보낼지는 어댑터가 결정한다.

## 3. 전송

§3.1~3.3은 공유메모리 전송, §3.6은 소켓 전송이다. 레코드 형식(§3.4)과 판정 의미(§3.5)는 같다.

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
| s2c | `POLICY=0x85` | `version:u32 count:u16 rsv:u16` + count×`(mode:u8 len:u8 name[len])`. 엔드포인트 정책(§10.2). mode: 1 off, 2 detect, 3 prevent |

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
- 크레딧 없이 오는 레코드(BYPASS, FLOW_ERROR, POLICY)는 s2c의 절반이 비어 있을 때만 보낸다. 그래서 이런 레코드가 쌓여도 판정 레코드는 항상 들어간다. BYPASS와 FLOW_ERROR는 자리가 없으면 버리고, POLICY는 자리가 날 때까지 다음 처리 패스마다 다시 보낸다.
- 엔드포인트 정책이 off나 detect인 엔드포인트(OPEN 메타 `endpoint`)의 flow는 차단하지 않는다. drop 판정이 나와도 `action=pass`로 보내고, `reason`은 원래 값(예: `rule`)을 유지한다. alert도 그대로 싣는다. 정책을 모르는 오래된 어댑터도 막지 않게 하기 위해서다. 카운터는 `suritap.detect_passes`다.

### 3.6 소켓 전송 (`worker-N.stream.sock`, `SOCK_STREAM`)

공유메모리를 매핑할 수 없는 클라이언트용이다. 같은 워커가 같은 엔진으로 처리하므로 판정 결과는 공유메모리와 같다. 차이는 지연과 처리량뿐이다(시스템콜과 복사가 레코드마다 생긴다).

1. 클라이언트가 HELLO(64B, §3.3과 같은 형식)를 보낸다. `flags=1`(소켓 전송), fd는 없다.
2. 서버가 WELCOME(64B)을 보낸다. fd는 없다. `max_payload`는 64 KiB다.
3. 이후 양방향 모두 §3.4의 레코드를 `len:u32 kind:u16 flags:u16 body` 프레임으로 이어 보낸다. 링과 달리 8바이트 정렬 패딩과 PAD 레코드가 없다.

| 항목 | 값 |
|---|---|
| 최대 프레임(클라이언트 → 서버) | `8 + 16 + 64 KiB`(64 KiB DATA). 넘으면 세션을 닫는다 |
| 동시 판정 요청 | 1024(`STREAM_MAX_INFLIGHT`). 판정이 늦게 와도 도착할 때까지 자리를 차지한다 |
| 서버 출력 버퍼 | 1 MiB. 클라이언트가 판정을 읽지 않아 넘치면 세션을 닫는다 |
| 서버 입력 버퍼 | 최대 프레임의 4배. 넘으면 읽기를 멈춘다(역압) |

HELLO 타임아웃, 대기 연결 상한, 세션 수 상한은 공유메모리와 같다. 연결이 끊기면 그 세션의 열린 flow를 RST로 정리한다. `suritap.stream: no`로 끌 수 있다.

## 4. 패킷 합성 (`tap/suritap/src/engine.rs`)

- **연결 수립**: OPEN을 받으면 실제 클라이언트 주소와 리스너 주소 사이에 IPv4 또는 IPv6 3-way handshake를 합성한다. SYN에는 MSS 65495와 WS 14 옵션을 넣는다.
- **데이터**: DATA는 `max-segment`(기본 32 KiB) 이하의 PSH|ACK 세그먼트로 나눈다. seq는 ISN과 오프셋으로, ack는 상대 방향 누적값으로 계산한다.
- **ACK 보충**: 한 방향의 미확인 바이트가 `ack-threshold`를 넘으면 상대 쪽에서 pure ACK를 넣는다.
- **종료와 GAP**: EOF는 FIN과 상대 ACK로, CLOSE는 FIN 양방향 또는 RST로 바꾼다. GAP은 seq를 건너뛰고 상대 ACK를 넣어 엔진이 gap으로 인식하게 한다.
- **연결 구분자**: 연결마다 (session, cid)에서 파생한 VLAN id 2개(각 1..4094, 약 24비트)를 붙인다. 자세한 이유는 §7.1을 본다. 값은 해시가 아니라 `(cid + 세션별 오프셋) mod 4094²`이다. 클라이언트는 cid를 카운터로 매기므로, 한 세션에서 4094²(약 1677만) 연결 안에서는 겹치지 않는다. HTTP/2 연결 하나는 같은 주소 쌍 위에 수천 개의 합성 flow를 만든다. 무작위 24비트 값을 쓰면 벤치마크 한 번에 수십 건이 겹쳤다. 대부분은 Suricata가 `tcp_reuse`로 처리하지만, 아직 살아 있는 flow와 겹치면 오탐 drop이 날 수 있다. 필요 조건은 `vlan.use-for-tracking: true`(기본값)이고, EVE에 `vlan`이 표시된다.
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
- 플러그인 통계 카운터는 `suritap.sessions/records/packets/bytes/verdicts/drops/flows/errors/bypasses/keepalives/detect_passes`다.

### 5.2 설정 (`suritap:`)

| 키 | 기본값 | 설명 |
|---|---|---|
| `socket-dir` | `/run/suritap` | `worker-N.sock`, `worker-N.stream.sock` 생성 위치. `--capture-plugin-args`로 덮어쓸 수 있다. 접근 제어는 디렉터리 권한으로 한다 |
| `stream` | `yes` | 소켓 전송(§3.6) 리스너 |
| `socket-mode` | — | 소켓 chmod(8진수) |
| `threads` | `auto` | 워커 수 |
| `ips` | `yes` | IPS 모드(판정에 drop 포함). `no`면 IDS 모드라 drop 룰도 alert로만 동작한다 |
| `max-sessions` / `max-flows` / `max-worker-flows` | 256 / 65536 / 262144 | 워커당 세션 수 / 세션당 flow 수 / 워커 전체 flow 수 |
| `max-segment` / `ack-threshold` | 32kb / 32kb | 합성 세그먼트 크기 / pure ACK 기준(§7.5: HTTP 바디 minimal inspect size의 3배보다 충분히 작게) |
| `max-region-size` | 64mb | 받아들이는 region 상한 |
| `policy-file` | — | 엔드포인트 정책 파일(§10.2). 바뀌면 다시 읽고(최대 약 2초) 모든 세션에 POLICY로 보낸다. 내용이 잘못되면 이전 정책을 유지한다 |
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
- 기한 안에 링에 넣지 못한 페이로드는 GAP으로 보고한다. 공간이 있으면 바로, 없으면 그 방향의 다음 페이로드 앞에 보낸다. 그래서 엔진이 구멍 너머의 바이트를 이어 붙이지 않는다(Go 클라이언트).
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

3단계에서 같은 문제가 다른 형태로 다시 나왔다. 엔진은 ACK 기준을 레코드가 끝난 뒤에만 확인했다. 그래서 64 KiB 레코드(32 KiB 세그먼트 두 개)로 바디를 보내면, 300 KiB 지점의 마커를 놓쳤다. Kong은 버퍼링한 바디를 한 번에 보내고, 소켓 전송의 레코드 상한이 64 KiB이기 때문에 드러났다. 지금은 세그먼트마다 확인한다. 회귀 테스트는 `body-large-records`이며, 600 KiB 바디를 Inspect 한 번으로 보낸다.

## 8. Traefik 어댑터 (2단계)

### 8.1 연결 방식

| | 플러그인 (기본) | 패치 빌드 |
|---|---|---|
| 코드 | `adapters/traefik-plugin` | `adapters/traefik` + `deploy/traefik` |
| Traefik | 공식 바이너리 그대로. Yaegi 인터프리터가 소스를 로드한다 | v3.7.14에 패치를 적용해 직접 빌드 |
| 전송 | 소켓(§3.6) | 공유메모리 |
| 적용 단위 | 라우터별 미들웨어 | 엔트리포인트(라우팅 전) |
| HTTP(1.1, h2, h3) | 지원 | 지원 |
| TLS 종단 TCP 라우터 | 미지원(Traefik 플러그인 API가 HTTP 미들웨어만 제공) | 지원 |
| 처리량(§8.6) | suritap 없음 대비 약 25% | 약 60~80% |

HTTP 처리 로직(요청 정규화, 바디·응답 처리, 차단 응답)은 하나다. 플러그인 패키지가 `Transport` 인터페이스 위에 구현하고, 패치 빌드는 같은 핸들러에 공유메모리 클라이언트를 `Transport`로 끼운다(`plugin.NewHandler`).

| 대상 | 방식 | 이유 |
|---|---|---|
| HTTP | **transaction tap**: 요청마다 HTTP/1.1로 정규화하고, 요청 하나를 합성 flow 하나로 검사한다 | `http.Server`는 `*tls.Conn` 타입 단언으로 ALPN(h2)과 `r.TLS`를 처리한다. 그래서 TLS 연결을 감싸면 HTTP/2가 깨진다. 또 h2와 h3의 다중화 스트림은 하나의 HTTP/1.1 바이트 스트림으로 표현할 수 없다 |
| TLS를 종단하는 TCP 라우터(패치 빌드) | **stream tap**: 복호화된 `net.Conn`을 감싸 모든 Read와 Write를 검사한다 | 프로토콜과 무관하다(pgsql, MQTT 등) |

### 8.2 플러그인 설정

플러그인은 표준 라이브러리만 쓰므로 `unsafe`/`syscall` 허용(`useUnsafe`)이 필요 없다. 로컬 플러그인으로 쓸 때는 소스를 Traefik 작업 디렉터리의 `plugins-local/src/github.com/jc-lab/suritap-traefik/`에 둔다(`go.mod`, `.traefik.yml`, `*.go`).

```yaml
# static
experimental:
  localPlugins:
    suritap:
      moduleName: github.com/jc-lab/suritap-traefik

# dynamic
http:
  middlewares:
    tap:
      plugin:
        suritap:
          socketDir: /run/suritap
          endpoint: websecure    # EVE의 suritap.endpoint (기본: 미들웨어 이름)
          mode: prevent          # prevent | detect
          response: detect       # off | detect | prevent
          failPolicy: open       # open | closed
          timeout: 100ms
          maxRequestBody: 1048576
          maxResponseBuffer: 65536
  routers:
    app:
      rule: Host(`app.example.com`)
      middlewares: [tap]
      service: app
      tls: {}
```

| 키 | 기본값 | 설명 |
|---|---|---|
| `mode` | `prevent` | `prevent`: drop 판정이면 차단한다. `detect`: 판정을 기다리지 않는다 |
| `response` | `detect` | 응답 검사 방식. `prevent`면 `maxResponseBuffer`까지 버퍼링한 뒤 응답 전체를 판정한다 |
| `failPolicy` | `open` | 판정을 받지 못했을 때(Suricata 없음, timeout, `error` 판정) 통과(`open`)할지 503(`closed`)을 줄지. drop 판정은 403이다 |
| `timeout` | `100ms` | 판정 대기 시간 |
| `maxRequestBody` | 1 MiB | 이 크기 이하의 요청 바디는 버퍼링하고 판정한 뒤 업스트림으로 보낸다. 큰 바디는 업스트림이 읽는 동안 청크마다 판정한다 |
| `maxResponseBuffer` | 64 KiB | prevent 응답을 버퍼링할 최대 크기 |
| `name` / `endpoint` | `traefik` / 미들웨어 이름 | EVE의 `suritap.client` / `suritap.endpoint` |

- 같은 `socketDir`과 `name`을 쓰는 미들웨어는 워커 세션을 공유한다. 세션은 첫 요청 때 열고, 끊기면 다음 요청 때 다시 연다.
- 세션 관리(소켓 전송 클라이언트):
  - 세션을 여는 동안 transport 잠금을 잡지 않는다. 응답하지 않는 워커가 있어도 다른 워커의 요청은 영향을 받지 않는다. 열리는 중인 세션을 기다리는 요청은 `timeout`까지만 기다린다.
  - 한 워커의 재연결이 실패해도 다른 워커의 세션은 그대로 둔다. 워커 수가 바뀐 것(Suricata 재시작)을 알게 되면 이전 세션을 모두 닫고 다시 구성한다.
  - 프레임은 통째로만 쓴다. 요청의 `timeout`은 프레임 사이에서만 확인하고, 남은 페이로드는 GAP으로 보고한다. 프레임 하나를 5초 안에 쓰지 못하면 그 세션만 끊는다. 그래서 느린 요청 하나가 같은 세션의 다른 요청을 실패시키지 않는다.
  - 판정 요청이 timeout될 때 마지막 판정 이후 5초가 지났거나, 판정 슬롯이 바닥났는데 절반 이상을 timeout된 요청이 차지하고 있으면 워커가 멈춘 것으로 보고 세션을 다시 연다.
  - 5분 동안 트래픽이 없는 세션은 닫는다. Traefik 플러그인에는 종료 콜백이 없어서, 설정이 바뀌어 쓰이지 않게 된 세션을 이렇게 정리한다.
- 로그: 차단과 오류는 stderr(Traefik이 ERROR로 기록), 나머지는 stdout(DEBUG)으로 나간다. Suricata에 닿지 못한다는 로그는 10초에 한 번만 남긴다.

### 8.3 패치 빌드 설정

패치(`deploy/traefik/traefik-v3.7.14.patch`, 4개 파일, 50여 줄)는 다음을 한다.

1. `static.EntryPoint`에 `Suritap *suritaptraefik.Config` 필드를 추가한다. 그래서 static 설정(파일, CLI, 환경 변수)으로 그대로 설정할 수 있다.
2. `newHTTPServer`에서 forwarded-headers 처리 직후, 라우팅 전에 `suritaptraefik.Middleware`를 끼운다. HTTP와 HTTPS 서버에 모두 적용되고, h3 서버도 같은 핸들러를 쓴다.
3. `tcp.Manager`에서 TLS를 종단하는 TCP 라우터의 핸들러를 `suritaptraefik.WrapConn`으로 감싼다.
4. 어댑터 로그를 Traefik zerolog로 보낸다(`pkg/server/suritap.go`).

```sh
make traefik            # deploy/traefik/build.sh → bin/traefik-suritap (v3.7.14-suritap)
```

```yaml
entryPoints:
  websecure:
    address: ":443"
    suritap:             # 키와 기본값은 §8.2와 같다(endpoint 기본값은 엔트리포인트 이름)
      socketDir: /run/suritap
      mode: prevent
```

빌드 스크립트는 지정한 태그를 받아 패치를 적용하고, 이 저장소를 `replace`로 연결해 빌드한다. 그 결과 Traefik의 `golang.org/x/*`와 `klauspost/compress`는 마이너 버전이 올라간다. 패치한 패키지의 Traefik 단위 테스트는 통과했다. 대시보드 정적 파일은 빌드하지 않는다.

### 8.4 동작

- **차단 응답:** 차단된 요청은 403과 함께 `X-Suritap-Cid`를 받는다. 이 값은 EVE의 `suritap.cid`와 같다. 이때 업스트림이 이미 설정한 헤더(Set-Cookie 등)는 버린다.
- **큰 요청 바디:** 업스트림이 읽는 동안 판정한다. 중간에 drop되면 업스트림 요청을 끊고 클라이언트에는 403을 준다.
- **응답 prevent:** 작은 응답은 끝까지 모아 한 번에 판정한다. chunked 응답이면 종료 청크까지 포함한다. Suricata는 메시지가 끝나야 작은 바디를 검사하기 때문이다. 큰 응답은 스트리밍 중에 drop이 나면 연결을 중단한다. 핸들러가 Flush하면(SSE, long polling) 그때까지의 내용을 판정한 뒤 바로 보내고, 이후로는 스트리밍으로 판정한다.
- **WebSocket 등 Upgrade:** 핸드셰이크 요청까지만 검사한다.
- **메타데이터:** SNI, ALPN, HTTP 버전, 엔트리포인트, `X-Request-Id`를 보낸다. TCP는 라우터 이름(`name@provider`)도 보낸다. 모두 EVE의 `suritap.*`에 남는다.
- **Suricata 쪽 설정:** 리스너 주소를 `HOME_NET`에 넣어야 인바운드 룰이 적용된다(§5.3).

### 8.5 검증 (`test/tap/traefik.sh`, Suricata 8.0.7 + Traefik 3.7.14)

```sh
SURICATA_PREFIX=... SURICATA_SRC=... test/tap/traefik.sh            # 공식 Traefik + 플러그인 → ALL PASSED
SURICATA_PREFIX=... SURICATA_SRC=... test/tap/traefik.sh --patch    # 패치 빌드 → ALL PASSED
```

기본 모드는 공식 v3.7.14 릴리스를 내려받아 체크섬을 확인한 뒤, 플러그인을 로컬 플러그인으로 로드한다. Traefik 로그에 panic이나 크래시가 있으면 실패로 본다.

| 항목 | 결과 |
|---|---|
| h2와 h1의 정상 요청 / URI 공격 | 200 / 403 |
| 작은 바디 공격(h2), 스트리밍 바디 공격(h1, 300 KiB 지점) | 403. 작은 바디 공격은 백엔드에 닿지 않는다 |
| reject 룰(User-Agent) | 403 |
| 응답 유출 룰: detect / prevent 미들웨어(엔트리포인트) | 200(EVE alert) / 403 |
| suritap이 없는 라우터(엔트리포인트) | 그대로 통과 |
| TLS 종단 TCP 라우터(패치 빌드만) | 정상 echo는 통과, 공격 바이트는 연결 종료 |
| EVE 메타데이터 | `proxy=traefik, endpoint, sni, alpn=h2, proto` (+ 패치 빌드 TCP는 `route=echo@file`) |
| Suricata 중지 시 | fail-open은 200, fail-closed는 503 |
| 차단 로그 | Traefik 로그에 `suritap: blocked … sids=[…]` |

HTTP/3는 같은 핸들러를 거친다. 다만 이 환경의 curl이 h3를 지원하지 않아 E2E에서는 빠졌다.

Yaegi 호환성은 `test/tap/yaegi`에서 따로 확인한다. Traefik 플러그인 로더와 같은 방식(GOPATH 레이아웃, `CreateConfig` 후 reflection으로 필드 설정, `New` 호출)으로 플러그인을 실행하고, suritap-mockd 또는 실제 Suricata를 상대로 기능 시나리오, 부하(16 클라이언트 × 300 요청, 판정 timeout 0건), 판정을 보내지 않는 서버를 상대로 한 timeout(동시 요청 모두 timeout 시각에 503), 리버스 프록시를 거친 스트리밍 요청 바디(업스트림 transport goroutine이 바디를 읽는 경로)와 Flush되는 응답을 검사한다. Yaegi 자체의 내부 data race 때문에 이 하네스는 `-race` 없이 돌린다(플러그인의 네이티브 테스트는 `-race`).

### 8.6 오버헤드 (`--bench`, GET 요청과 짧은 응답, 16 클라이언트, 소규모 룰, 워커 2개)

모든 프로세스가 같은 호스트에서 CPU를 나눠 쓴 조건이다. "prevent"는 요청 prevent·응답 detect, "응답 prevent"는 둘 다 prevent·fail closed다.

| | suritap 없음 | prevent | 응답 prevent |
|---|---|---|---|
| 플러그인, HTTP/2 | 27.6k req/s, p50 0.54ms | 7.6k, p50 1.9ms, p99 4.7ms | 6.9k, p50 2.1ms, p99 5.1ms |
| 플러그인, HTTP/1.1 | 28.5k, p50 0.49ms | 6.4k, p50 2.2ms, p99 6.5ms | 7.1k, p50 2.0ms, p99 5.4ms |
| 패치 빌드, HTTP/2 | 25.3k, p50 0.58ms | 21.1k, p50 0.71ms, p99 1.7ms | 20.8k, p50 0.74ms, p99 1.5ms |
| 패치 빌드, HTTP/1.1 | 32.8k, p50 0.43ms | 18.7k, p50 0.78ms, p99 2.3ms | 19.4k, p50 0.79ms, p99 1.8ms |

- 패치 빌드의 요청당 추가 지연은 약 0.2~0.3ms다. 요청마다 합성 flow를 열고 닫는 비용(패킷 약 9개)이 대부분이다.
- 플러그인의 추가 비용(약 1.5ms)은 대부분 Yaegi 해석 실행이다. 같은 플러그인 코드를 네이티브로 컴파일해 소켓 전송으로 돌리면 14.8k req/s가 나온다.

### 8.7 Yaegi(v0.16.1)에서 확인한 제약

공식 Traefik 바이너리에서 플러그인을 돌리며 확인한 것들이다. 플러그인 코드는 다음을 모두 피한다.

| 구문 | 증상 |
|---|---|
| 여러 goroutine이 동시에 실행하는 `select` 문 | 한 `select` 문의 case 목록(`reflect.SelectCase` 슬라이스)을 모든 goroutine이 공유한다. 다른 요청의 채널을 기다리게 되어 판정 timeout과 멈춤이 생긴다. `select <-ctx.Done()`도 같은 원인으로 오동작한다. `context` 자체와 단일 채널 송수신은 안전하다 |
| 인터프리트된 타입의 채널을 담은 map·slice(`map[uint32]chan reply`) | 인터프리터 크래시 |
| `sync.Once.Do` 안의 클로저, range 중 map 삭제 | 인터프리터 크래시 |
| 구조체 필드에 대한 `sync/atomic`(여러 goroutine) | 인터프리터 크래시 |
| nil 인터페이스에 대한 comma-ok 타입 단언 | panic |
| 지역 변수가 많은 함수 안의 `for … range` | range 대상 슬롯을 다른 지역 변수와 혼동해 panic(`reflect: call of reflect.Value.Len on int Value`). 해당 위치는 인덱스 루프로 바꿨다 |
| 플러그인 goroutine의 panic | Traefik 프로세스 전체가 종료된다. 백그라운드 goroutine은 `recover`로 감싼다 |

그래서 소켓 클라이언트는 판정 대기를 고정 슬롯(`[]chan []byte`)에 두고, ctx 취소·timeout은 `select` 대신 `context.AfterFunc`가 대기 채널에 표시값을 넣는 방식으로 받는다. 인터페이스는 Go 관례대로 ctx를 받고(`Inspect(ctx, …)`), 요청 ctx를 부모로 쓰므로 클라이언트가 끊기면 대기도 바로 끝난다. 동시 판정 수는 슬롯 free list로 제한한다.

해석 실행에서는 함수 호출과 `defer`가 비싸다. 요청마다 도는 경로(잠금 보조 함수 등)에 이것들을 넣었을 때 하네스 부하 테스트가 11k에서 9k req/s로 떨어졌고, 인라인으로 바꾸자 11k로 돌아왔다.

## 9. Kong 어댑터 (3단계)

### 9.1 구조

Kong 플러그인은 순수 Lua로 작성했고, 소켓 전송(§3.6)을 OpenResty cosocket으로 쓴다. C 모듈이나 Kong 재빌드는 필요 없다.

- **전송(`kong/plugins/suritap/transport.lua`)**
  - cosocket은 만든 요청(또는 timer)에 묶이고, header_filter·body_filter·log 단계에서는 쓸 수 없다. 그래서 nginx 워커마다, Suricata 워커마다 timer 하나가 세션 소켓을 가진다. timer 안에서 writer 루프와 reader light thread가 돈다.
  - 요청은 프레임을 큐에 넣고, 판정은 `ngx.semaphore`로 기다린다. 큐에 넣는 것은 yield하지 않으므로 모든 단계에서 쓸 수 있다. 판정을 기다리는 것은 yield가 가능한 단계(access, response)에서만 한다.
  - 세션 관리는 Go 클라이언트와 같다.
    - 세션이 열리는 동안 요청은 timeout까지만 기다린다.
    - 워커 수가 바뀌면 이전 세션을 모두 닫는다.
    - timeout된 판정 요청은 슬롯을 늦은 판정이 올 때까지 잡아 둔다. 판정이 5초 동안 없으면 세션을 다시 연다.
    - 5분 동안 트래픽이 없으면 세션을 닫는다.
    - worker가 종료 중(`ngx.worker.exiting()`)이면 timer를 끝낸다. nginx는 graceful shutdown 때 실행 중인 timer를 기다리기 때문이다.
  - 세션당 큐는 8 MiB까지다. 넘친 페이로드는 버리고 GAP으로 보고한다.
- **`suritap` 플러그인(PRIORITY 1500)**
  - access 단계: Kong이 버퍼링한 요청을 HTTP/1.1로 정규화해 판정을 기다린다. drop이면 403과 `X-Suritap-Cid`를 준다. 인증 플러그인(jwt 1450, key-auth 1250 등)보다 먼저 돌아서, 인증이 거절할 요청도 검사한다.
  - header_filter·body_filter 단계: 응답 detect. 응답을 기다리지 않고 스트리밍으로 보낸다.
  - log 단계: 연결을 닫는다.
- **`suritap-response` 플러그인(PRIORITY 1499, 설정 없음)**
  - 응답 prevent. Kong의 buffered proxying이 응답 전체를 모은 뒤 response 단계에서 판정한다. drop이면 업스트림 헤더(Set-Cookie 등)를 지우고 403을 준다.
  - Kong은 response 단계와 header/body filter를 한 플러그인에 함께 두는 것을 허용하지 않는다. 그래서 별도 플러그인이고, `suritap` 플러그인이 연 flow를 `kong.ctx.shared`로 이어받는다.

### 9.2 설정

```yaml
# kong.conf: plugins = bundled,suritap,suritap-response
#            lua_package_path = /path/to/adapters/kong/?.lua;;
# (또는 luarocks make adapters/kong/kong-plugin-suritap-0.1.0-1.rockspec)
routes:
  - name: app
    hosts: [app.example.com]
    plugins:
      - name: suritap
        config:
          socket_dir: /run/suritap
          mode: prevent          # prevent | detect
          response: detect       # off | detect | prevent
          fail_policy: open      # open | closed
          timeout: 100           # 판정 대기, 밀리초
          max_request_body: 1048576
          max_response_body: 1048576
          endpoint: websecure    # EVE의 suritap.endpoint (기본: 라우트 이름)
      # response: prevent일 때만
      - name: suritap-response
```

| 키 | 기본값 | 설명 |
|---|---|---|
| `mode` | `prevent` | `prevent`: drop 판정이면 403. `detect`: 판정을 기다리지 않는다 |
| `response` | `detect` | `off`, `detect`(filter 단계에서 스트리밍), `prevent`(`suritap-response` 필요, 응답 전체를 버퍼링한 뒤 판정) |
| `fail_policy` | `open` | 판정을 받지 못했을 때(Suricata 없음, timeout, `error` 판정) 통과할지 503을 줄지 |
| `timeout` | 100 | 판정 대기 시간(ms). 세션이 열리기를 기다리는 시간도 포함한다 |
| `max_request_body` / `max_response_body` | 1 MiB | 검사할 바디 크기. 나머지는 GAP으로 보고한다 |
| `socket_dir` / `name` / `endpoint` | `/run/suritap` / `kong` / 라우트 이름 | 소켓 위치, EVE의 `suritap.client` / `suritap.endpoint` |

- **메타데이터:** 프로토콜, SNI, ALPN, `X-Request-Id`(없으면 Kong request id), 라우트 이름, 서비스 이름, 엔드포인트를 보낸다. 모두 EVE의 `suritap.*`에 남는다.
- **주소:** 출발지는 `remote_addr:remote_port`(Kong의 `trusted_ips`/real IP 처리 결과), 목적지는 리스너 주소다.
- **정규화:** `Expect` 헤더는 뺀다. nginx가 이미 `100 Continue`를 처리했다. 남겨 두면 Suricata(libhtp)가 그 응답을 기다리며 바디를 검사하지 않는다(실측).
- **소켓 권한:** Kong 워커 사용자가 `worker-N.stream.sock`에 쓸 수 있어야 한다(`suritap.socket-mode` 또는 그룹).

### 9.3 검증 (`test/tap/kong.sh`, Suricata 8.0.7 + 공식 `kong:3.9.1` 이미지)

```sh
test/tap/kong/transport.sh                                   # Lua 클라이언트 단독 → ALL PASSED
SURICATA_PREFIX=... SURICATA_SRC=... test/tap/kong.sh        # E2E → ALL PASSED
```

- `transport.sh`: suritap-mockd와 판정을 보내지 않는 서버를 상대로 검사한다. 항목은 pass/drop, IPv6, 프레임 분할, 동시 요청 1000건, 워커당 세션 하나, timeout 시각 준수, 멈춘 세션 재연결이다.
- `kong.sh`: DB-less 선언형 설정으로 Kong을 host 네트워크에 띄운다.

| 항목 | 결과 |
|---|---|
| h2와 h1의 정상 요청 / URI 공격 | 200 / 403 |
| 작은 바디 공격(h2), 600 KiB 바디의 300 KiB 지점 공격(h1) | 403. 차단된 요청은 백엔드에 닿지 않는다(Kong이 바디를 버퍼링) |
| reject 룰(User-Agent) | 403 |
| 응답 유출 룰: detect / prevent 라우트 | 200(EVE alert) / 403(업스트림 헤더 제거) |
| suritap이 없는 라우트 | 그대로 통과 |
| EVE 메타데이터 | `proxy=kong, endpoint, sni, alpn=h2, proto, route=app, service=backend` |
| Suricata 중지 시 | fail-open은 200, fail-closed는 503 |
| Kong 오류 로그 | 없음 |

### 9.4 오버헤드 (`--bench`, GET 요청과 짧은 응답, 16 클라이언트, nginx 워커 2개, 워커 2개)

같은 호스트에서 다른 작업이 돌던 조건이다(load average 약 6). 비율로 보는 것이 좋다.

| | suritap 없음 | prevent (응답 detect) | prevent (응답 prevent) |
|---|---|---|---|
| HTTP/2 | 13.8k req/s, p50 1.1ms | 6.8k, p50 2.1ms, p99 7.2ms | 5.6k, p50 2.5ms, p99 8.5ms |
| HTTP/1.1 | 19.9k, p50 0.76ms | 11.6k, p50 1.2ms, p99 3.6ms | 7.7k, p50 1.7ms, p99 6.8ms |

- 응답 prevent는 Kong의 buffered proxying(내부 subrequest)을 쓰므로 비용이 더 든다. 응답을 스트리밍하지 못한다.

처리량은 호스트 부하에 따라 크게 흔들렸다. 그래서 플러그인 비용은 nginx 워커 CPU 시간(`/proc/<pid>/stat`)을 요청 수로 나눠 쟀다. 조건은 suritap-mockd 상대, Kong과 mockd, 부하 생성기를 서로 다른 코어에 고정, 4만 요청 × 5회 번갈아 측정한 중앙값이다.

| 요청당 워커 CPU | suritap 없음 | prevent(응답 detect), 최적화 전 | 최적화 후 |
|---|---|---|---|
| HTTP/2 | 약 81µs | 131µs (+49µs) | 115µs (+34µs) |
| HTTP/1.1 | 약 94µs | 160µs (+66µs) | 149µs (+55µs) |

- **소켓 전송 자체는 작다.** Lua 클라이언트만 따로 돌리면 nginx 워커 하나당 약 11.5만 req/s가 나오고, 요청당 약 8.5µs다. 판정을 기다리지 않는 detect도 prevent와 비용이 비슷했다. 그래서 FFI로 memfd 공유메모리를 쓰는 안은 택하지 않았다.
  - 얻을 수 있는 몫이 작다.
  - LuaJIT은 링에 필요한 원자 연산(완전 펜스)을 낼 수 없다.
  - nginx 이벤트 루프는 Lua에서 eventfd를 기다릴 수 없다.
- **perf로 보니 비용은 대부분 메모리 할당과 GC다**(`lj_str_new`, `lj_alloc_free`, `gc_sweep`, `propagatemark`). Kong의 Lua 힙이 커서 할당한 바이트마다 GC 비용이 크다. 그래서 할당을 줄였다.
  - 프레임을 FFI 스크래치 버퍼에 써서 프레임당 문자열 하나만 만든다.
  - 판정은 받은 버퍼에서 바로 해석한다.
  - HTTP/1.x는 원본 헤더 블록(`ngx.req.raw_header`)을 그대로 쓰고, 헤더 직렬화는 `string.buffer`를 재사용한다.
  - semaphore를 재사용하고, 메타데이터는 플랫 배열로 만든다.
  - 응답 chunk 틀은 조각으로 넘겨 본문을 복사하지 않는다.

### 9.5 제약

- 응답 prevent는 응답 전체를 버퍼링한다. SSE나 long polling 라우트에는 `response: detect`를 쓴다.
- 요청 바디는 Kong이 버퍼링한 뒤 한 번에 판정한다. `max_request_body`를 넘는 부분은 검사하지 않고 GAP으로 보고한다.
- nginx가 거절하는 요청(루트 위로 올라가는 경로, `client_max_body_size` 초과 등)은 플러그인까지 오지 않는다.
- nginx 워커마다 Suricata 워커 하나당 세션을 하나씩 연다. 그래서 `suritap.max-sessions`(Suricata 워커당 세션 상한, 기본 256)는 "Kong 인스턴스 수 × nginx 워커 수"보다 커야 한다.

## 10. suricontroller 통합 (5단계)

### 10.1 전달 경로

```
suri-controller-web  ──(노드 › Proxy endpoints: Off / Detect / Prevent)
suri-controller      ──DesiredState.endpoint_modes──▶ suri-node-agent
suri-node-agent      ──정책 파일 /run/suri-agent/tap/policy (원자적 쓰기)
suritap.so           ──파일 변경 감지 → POLICY 레코드 (WELCOME 직후, 변경 시)──▶ 프록시 어댑터
Traefik / Kong 어댑터 ──엔드포인트별 off(건너뜀) / detect(대기 없음) / prevent(대기·차단)
```

- 엔드포인트 이름은 어댑터가 OPEN 메타 `endpoint`로 보내는 값이다. Traefik 플러그인은 `endpoint` 설정(기본: 미들웨어 이름), 패치 빌드는 엔트리포인트 이름, Kong은 `endpoint` 설정(기본: 라우트 이름)이다.
- 모드만 바꾸면 agent는 정책 파일만 다시 쓴다. `suricata -T`도 재시작도 없다. 프록시는 몇 초 안에 따라온다(플러그인 감지 최대 약 2초).
- 인터페이스 모드와 같은 규칙을 따른다.
  - 엔드포인트 목록과 prevent 허용 여부는 agent가 정한다(`agent.yaml`).
  - controller와 UI도 검증하지만 최종 판단은 agent의 POLICY 단계다.
  - controller가 지정하지 않은 엔드포인트는 off다.

### 10.2 정책 파일과 POLICY 레코드

```text
# Written by suri-node-agent: tap endpoint modes set by the controller.
websecure prevent
api detect
admin off
```

- 줄마다 `<엔드포인트> <off|detect|prevent>`다. 이름은 1~64자의 `A-Z a-z 0-9 . _ : @ / -`이고, 최대 256개다.
- 플러그인 워커가 housekeeping 주기마다 파일의 크기와 수정 시각을 확인한다. 바뀌었으면 다시 읽어 버전을 올리고 POLICY를 보낸다. 파일이 없으면 빈 정책이다.
- 클라이언트(Go `Client.EndpointMode`, Rust `Client::endpoint_mode`, Traefik 플러그인, Kong 전송)의 동작:
  - 마지막으로 받은 정책을 캐시하고, 세션이 끊겨도 유지한다(Suricata 재시작 중에도 off/detect가 유지된다).
  - 열린 세션이 없으면 모드를 조회할 때 백그라운드로 세션을 연다. 그래서 모든 요청이 off라 아무것도 보내지 않는 동안에도 정책 변경을 받는다.
  - 정책에 없는 엔드포인트는 어댑터 자체 설정을 따른다. controller 없이 쓰는 기존 구성은 그대로 동작한다.

### 10.3 어댑터 동작

| 정책 | Traefik(플러그인, 패치 빌드) | Kong |
|---|---|---|
| off | 검사 없이 다음 핸들러로. TCP 라우터는 감싸지 않음 | access 단계에서 바로 반환 |
| detect | 요청은 대기 없이 전송. 응답 prevent 설정은 detect로 낮춤 | 같음(`suritap-response`도 건너뜀) |
| prevent | 판정 대기, drop이면 403(`X-Suritap-Cid`) | 같음 |
| 목록에 없음 | 미들웨어/엔트리포인트 설정 | 플러그인 설정 |

### 10.4 agent 설정과 tap 인스턴스

```yaml
tap:
  enabled: true
  plugin: /usr/lib/suricata/suritap.so     # 기본값
  socket_dir: /run/suritap                 # 프록시와 공유(볼륨)
  socket_mode: "0666"                      # 또는 공용 그룹으로 제한
  threads: auto
  config: /etc/suricata/tap.yaml           # tap 인스턴스 전용 Suricata 설정
  endpoints:
    - name: websecure
      description: Traefik websecure
    - name: admin
      prevent: false                       # controller는 off/detect만 지정 가능
suricata:
  instances:
    tap: { log_dir: /var/log/suricata/tap }
```

- `tap.enabled`이면 `tap` 인스턴스(`--capture-plugin=suritap`)를 띄운다. 모든 엔드포인트가 off여도 띄운다. 어댑터가 off 정책을 받아야 하기 때문이다. 룰 번들은 ids·ips와 같은 것을 쓴다.
- 설정 병합 순서는 base(`suricata.yaml`) < `tap.config` < controller overlay < agent 런타임이다.
  - 런타임은 `plugins`와 `suritap.socket-dir/policy-file/threads/socket-mode/ips`를 강제한다.
  - §5.3의 권장값(depth 0, bypass no, `HOME_NET` = 프록시 리스너, body inspect size)은 다른 인스턴스와 공유하는 base 대신 `tap.config`에 둔다. 이미지가 기본 파일을 넣는다.
- 상태 보고(인스턴스 `tap`, capture `plugin`)에 `suritap.sessions/verdicts/drops/detect_passes/flows/errors` 카운터가 실린다. Hello에는 엔드포인트 목록과 플러그인 존재 여부가 실린다. 플러그인이 없으면 경고 `tap_plugin_missing`을 보낸다.
- tap 인스턴스의 EVE는 다른 인스턴스와 같이 수집된다. `suritap.*` 필드(endpoint, sni, route 등)로 걸러 볼 수 있다.

### 10.5 이미지

- `deploy/agent/Dockerfile`은 Alpine 패키지 대신 Suricata 8.0.7을 소스로 빌드한다(tarball SHA-256 고정, NFQ 포함). 같은 소스 트리로 `suritap.so`를 빌드해 `/usr/lib/suricata/suritap.so`에 넣는다. 플러그인은 정확히 같은 Suricata 빌드에만 로드되기 때문이다.
- 기본 `tap.yaml`을 `/etc/suricata`가 비어 있을 때 채운다. compose 예시는 `/run/suritap`을 볼륨으로 공유한다.
- 빌드는 컴파일 때문에 수 분 걸린다. 확인 단계에서 `suricata --build-info`(NFQ)를 검사하고, `suricata -T`로 플러그인이 로드되는지 확인했다.

### 10.6 검증 (`test/docker/integration.sh`)

실제 controller와 agent 이미지로 기존 시나리오(IDS, IPS, 검증 실패, 롤백, 재시작 복원)에 tap 시나리오를 더했다. ALL PASSED.

| 항목 | 결과 |
|---|---|
| Hello의 tap 정보(엔드포인트, 플러그인 존재) | controller API에 표시 |
| tap 인스턴스 | capture `plugin`으로 실행, ids·ips 전환과 무관하게 유지 |
| `SetEndpointModes web=PREVENT` | 적용 후 컨테이너 안 클라이언트(`suritap-probe inspect`)가 mode prevent를 받고, blockme 요청이 drop(sid 9000002) |
| `DETECT` | mode detect, 같은 요청이 `pass`(reason rule) |
| `OFF` | mode off |
| EVE 수집 | tap 인스턴스 alert가 `suritap.endpoint=web`과 함께 controller에 수집 |
| agent 재시작(controller 없이) | tap 소켓 복원 |

- controller: 노드 API에 `tap`(엔드포인트, 원하는 모드와 적용된 모드)을 추가했고, RPC `SetEndpointModes`(감사 로그 `node.tap_endpoints`)를 추가했다. sqlite 스키마는 v2(`endpoint_modes` 열, v1에서 자동 이전)다.
- web: 노드 상세의 "Proxy endpoints" 탭에서 엔드포인트마다 Off/Detect/Prevent를 고르고, 적용 상태(pending)를 본다. agent가 prevent를 허용하지 않으면 선택할 수 없다.
- `suritap-probe inspect -endpoint NAME`: 정책 모드와 판정을 JSON으로 출력하는 진단 도구다.

## 11. 알려진 제약과 다음 단계

- 단일 IPS 인스턴스에서 Detect(shadow) 모드로 쓰면, 처음 would-drop이 난 뒤로는 그 연결이 더 검사되지 않는다(flow drop).
- drop된 flow는 RST가 처리되지 않으므로 `flow-timeouts.tcp.established` 동안 엔진 메모리에 남는다. 구분자 덕분에 정확성 문제는 없다.
- 소켓에 접근할 수 있는 프로세스는 신뢰 경계 안에 있다. 세션·flow·메타데이터 상한으로 자원 사용은 제한하지만, 접근 제어는 소켓 디렉터리 권한으로 해야 한다.
- `suritap.so`는 Suricata 내부 헤더에 의존하므로 Suricata 버전마다 다시 빌드해야 한다.
- multi-tenant(`tenant` 필드는 예약됨)는 아직 없다. 데이터 경로 배치 최적화도 남아 있다.
- Traefik 어댑터의 제약:
  - 요청마다 합성 flow를 쓰므로, 같은 연결의 여러 요청에 걸친 공격은 보지 못한다. HTTP/1 연결 단위로 flow를 재사용하면 오버헤드도 줄일 수 있다.
  - HTTP 라우터와 서비스 이름은 메타데이터에 없다. 패치 빌드는 미들웨어가 라우팅 전에 있고, 플러그인 API는 라우터 정보를 넘겨주지 않는다. 플러그인에서는 미들웨어마다 `endpoint`를 다르게 줘서 구분한다.
  - 패치는 Traefik 버전마다 따로 유지해야 한다. 플러그인은 버전과 무관하지만 TCP 라우터를 검사하지 못하고 처리량이 낮다.
- 다음 단계:
  - Traefik 플러그인의 해석 실행 비용 줄이기(요청당 할당·프레임 수 감소)
  - agent 이미지는 Suricata 소스 빌드라 CI가 아키텍처마다 네이티브 러너에서 빌드한다(amd64, arm64). armv7은 CI에서 빌드하지 않고, 로컬 검증은 amd64만 했다.
- 엔드포인트 정책은 엔드포인트 단위다. 라우트나 경로 단위의 세분화는 어댑터 설정(미들웨어, 플러그인 인스턴스)으로 한다.
