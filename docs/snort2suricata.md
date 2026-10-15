# snort2suricata

Snort 2.9 / Snort 3 룰을 Suricata 8 룰로 변환합니다. 변환 로직은 `pkg/snortconv` 패키지에 있고, `cmd/snort2suricata`는 이를 감싼 CLI입니다.

```sh
go build -o bin/snort2suricata ./cmd/snort2suricata

# Snort 3 커뮤니티 룰
bin/snort2suricata -dialect snort3 -o community.rules \
  -rejected rejected.rules -report report.json snort3-community.rules

# Snort 2.9 커뮤니티 룰(주석 처리된 룰은 주석 상태로 변환)
bin/snort2suricata -o community.rules community.rules
```

| 옵션 | 설명 |
|---|---|
| `-dialect auto\|snort2\|snort3` | 입력 문법. `auto`는 파일 단위로 판별합니다. |
| `-o` | 변환 결과(기본 stdout) |
| `-rejected` | 변환하지 못한 룰과 이유 |
| `-report` | JSON 리포트(룰별 상태와 이슈) |
| `-exact-only` | 근사(approx) 변환 룰도 거부합니다. |
| `-enable-all` | 주석 처리된 룰을 활성화해서 변환합니다. |

룰마다 결과는 셋 중 하나입니다.

- **exact**: 두 엔진의 버퍼가 대응하는 범위에서 같은 데이터를 같은 조건으로 검사합니다.
- **approx**: 의미가 달라지는 부분이 있습니다. 출력에 `# snort2suricata: approx: <이유>` 주석이 붙습니다.
- **failed**: Suricata에 대응 기능이 없습니다. 출력에서 빠지고 `-rejected`에 이유와 함께 기록됩니다.

## 변환 규칙

| Snort | Suricata | 근거 |
|---|---|---|
| Snort 2 content modifier(`http_uri` 등), pcre 버퍼 플래그(`/U`, `/H`, …) | sticky buffer(`http.uri` 등), 플래그 제거 | Suricata 8은 sticky buffer가 표준입니다. |
| Snort 2 `fast_pattern:only` | `nocase; fast_pattern;` | Snort 2는 fast pattern을 대소문자 구분 없이 넣고 다시 확인하지 않습니다(snort2lua도 `fast_pattern,nocase`로 바꿉니다). Suricata의 `fast_pattern:only`는 대소문자를 구분합니다. |
| Snort 2 `urilen:N` | `urilen:N,raw` | Snort 2 기본값은 raw URI이고, Suricata 기본값은 정규화 URI입니다. |
| Snort 2 `urilen:a<>b`, Snort 3 `a<=>b` | `(a-1)<>(b+1)` | Snort 범위는 경계를 포함하고, Suricata `<>`는 포함하지 않습니다. |
| Snort 3 `bufferlen` | `bsize`(패킷이면 `dsize`). `relative`이면 `isdataat:…,relative` | |
| `flowbits:set,a&b` | `flowbits:set,a; flowbits:set,b;` | Suricata는 `&`를 비트 이름의 일부로 취급해서 `a`, `b`가 설정되지 않습니다. |
| 버퍼가 바뀐 직후의 relative 옵션 | 절대 위치(`offset`/`depth`)로 변환, pcre `R` 제거 | Snort는 버퍼를 바꾸면 커서를 버퍼 처음으로 옮깁니다. Suricata는 같은 버퍼에 다시 들어가면 이전 매치 뒤에서 이어갑니다. |
| 같은 버퍼가 여러 번 나오는 룰 | 버퍼별로 묶어서 한 번만 선택 | Suricata의 "duplicate instance" 경고와 multi-instance 버퍼의 의미 변화를 막습니다. byte_extract 변수가 정의 전에 쓰이게 되면 묶지 않습니다. |
| `sip_method`, `sip_stat_code` | `sip.method`/`sip.stat_code` + `startswith`/`endswith`/`bsize` | 부분 일치를 막습니다(`sip_stat_code:4`는 4xx 전체). |
| `dce_iface:uuid X`(Snort 3), `dce_opnum:"N"` | `dce_iface:X`, `dce_opnum:N` | DCERPC over TCP/UDP/SMB 모두 Suricata가 지원합니다. |
| `raw_data`, `rawbytes` | payload | Suricata payload는 원래 정규화하지 않은 데이터입니다. |
| `stream_size:N,to_client`(Snort 3) | `stream_size:server,=,N` | snort2lua의 server↔to_client 대응을 따릅니다. |
| `tag:session,packets 5`(Snort 3) | `tag:session,5,packets` | |
| `alert http (...)`, `alert ssl (...)` | `alert http any any -> any any`, `alert tls …` | |
| `sdrop`, `block` | `drop`(+`noalert`) | |
| Suricata의 제약 | 두 번째 `fast_pattern`, 부정+상대 위치 content의 `fast_pattern` 제거 | `fast_pattern`은 성능에만 영향을 줍니다. |

`service`(Snort 3)와 `metadata: service`(Snort 2)는 헤더나 `app-layer-protocol`로 바꾸지 않고 포트 기반 헤더를 유지합니다. Snort 3는 서비스를 식별하지 못한 흐름을 포트로 검사하는데, `app-layer-protocol`을 붙이면 Suricata가 프로토콜을 인식하지 못하는 비정상 트래픽(익스플로잇에서 흔합니다)을 놓칩니다. HTTP sticky buffer처럼 프로토콜이 필요한 키워드가 있으면 Suricata가 알아서 app-layer로 제한합니다.

### 변환하지 않는 것

- `ber_data`, `ber_skip`, `http_param`, `js_data`, `vba_data`, `sd_pattern`, flowbit group 등 Suricata에 대응 기능이 없는 옵션
- 패킷 단위 옵션(`flags`, `dsize`, `id`, `fragbits` …)과 app-layer 버퍼를 같이 쓰는 룰. Suricata가 거부합니다.
- 요청 버퍼와 응답 버퍼를 같이 쓰는 룰. Suricata의 `=>` 트랜잭션 룰은 의미가 다릅니다.
- `sip_header`/`sip_body`는 SIP payload 전체에서 검사하는 approx로 변환합니다. Suricata에는 SIP 헤더만 담는 버퍼가 없습니다.

### Suricata 설정

Snort 룰은 `$SIP_SERVERS`를 쓰는데, 기본 `suricata.yaml`에는 정의되어 있지 않습니다. `vars.address-groups`에 추가하거나 `--set 'vars.address-groups.SIP_SERVERS=$HOME_NET'`을 줍니다.

## 검증

`scripts/snort2suricata-validate.sh`는 커뮤니티 룰을 받아 변환하고 Suricata(`$SURICATA` 또는 alpine 컨테이너)로 로드를 확인합니다.

2026-10-15 커뮤니티 룰(Snort 2: 4,013개, Snort 3: 4,017개) 기준 결과입니다.

| | Snort 2 | Snort 3 |
|---|---|---|
| exact | 4,010 | 4,011 |
| approx | 2(sip_header) | 2(sip_header) |
| failed | 1(packet+app-layer) | 4(ber_data 2, http_param 1, packet+app-layer 1) |
| Suricata 8.0.7 로드 오류/경고 | 0 / 0 | 0 / 0 |

정확도는 다음 방법으로 확인했습니다.

- **교차 검증**: Talos가 관리하는 Snort 3 커뮤니티 룰은 같은 SID의 Snort 2 룰을 변환한 것입니다. 두 입력을 각각 변환한 결과를 의미 단위(버퍼별 content/pcre/byte 옵션, 헤더, 기타 옵션)로 비교하면 공통 SID 4,005개 중 3,980개가 같습니다. 나머지 25개는 Talos가 Snort 3판에서 룰 자체를 고친 경우입니다(헤더를 `http`로 변경, content 수정 등).
- **pcap 실측**(Suricata 8.0.7): `flowbits:set,a&b`가 `a`/`b`를 설정하지 않는 것, `fast_pattern:only`가 대소문자를 구분하는 것, `urilen` raw/정규화 차이, `sip.method`/`sip.stat_code`, `dce_iface`/`dce_opnum`/`dce_stub_data` 변환이 의도대로 탐지되는 것을 확인했습니다.
