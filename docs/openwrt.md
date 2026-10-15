# OpenWRT에 suri-node-agent 설치

이 문서는 docker 방식 설치를 다룹니다. OpenWRT에 Suricata 패키지가 정식으로 들어오면 native 방식(`platform.profile: openwrt-native`)도 지원할 예정입니다.

## 요구 사항

- **아키텍처**: x86_64, aarch64, armv7. docker 이미지는 Alpine 기반입니다.
- **저장 공간**: overlay 외에 USB나 eMMC 같은 저장 공간이 필요합니다. docker 이미지와 Suricata 룰 때문입니다.
- **메모리**: 1GB 이상을 권장합니다. 실제로 필요한 양은 룰셋 크기에 따라 달라집니다.
  - ET Open 전체를 쓰면 IDS 인스턴스 하나에 수백 MB가 듭니다.
  - IDS와 IPS 인터페이스를 섞으면 인스턴스가 2개라서 약 2배가 됩니다.
  - 노드별 `sources.yaml`이나 `disable.conf`로 룰을 줄이면 메모리를 아낄 수 있습니다.

## 1. docker 설치

```sh
opkg update
opkg install dockerd docker docker-compose luci-app-dockerman   # luci-app-dockerman은 선택
/etc/init.d/dockerd enable && /etc/init.d/dockerd start
```

docker data-root는 외부 저장 장치에 두는 것을 권장합니다(`/etc/config/dockerd`의 `data_root`).

### IPS를 쓰려면: NFQUEUE 커널 모듈

IPS는 트래픽을 NFQUEUE로 Suricata에 넘깁니다. OpenWrt 기본 이미지에는 이 커널 모듈이 없으므로 설치해야 합니다. IDS(af-packet)만 쓴다면 필요 없습니다.

```sh
opkg update
opkg install kmod-nft-queue kmod-nfnetlink-queue      # fw4(nftables)
# iptables(legacy)를 쓰는 구성이면: opkg install kmod-ipt-nfqueue iptables-mod-nfqueue kmod-nfnetlink-queue
```

- 모듈이 없을 때 nft는 엉뚱한 메시지를 냅니다: `Error: No such file or directory; did you mean table 'fw4' in family inet?`
- 에이전트는 시작할 때 `nft -c`로 queue 지원 여부를 미리 확인합니다(커널까지 확인하지만 아무것도 적용하지 않음). 지원하지 않으면 다음과 같이 동작합니다.
  - 경고 `nfqueue_unsupported`에 설치할 패키지를 적어 보고합니다.
  - 인터페이스를 IPS 불가로 보고하므로, controller UI에서 IPS를 고를 수 없습니다.
  - IPS 요청은 방화벽을 건드리기 전에 POLICY 단계에서 거부합니다.
- 모듈을 설치하면 5분 안에 다시 확인해 IPS를 허용합니다. 바로 반영하려면 에이전트를 재시작합니다.

## 2. 에이전트 설정

```sh
mkdir -p /opt/suri-agent/etc /opt/suri-agent/suricata /opt/suri-agent/data /mnt/data/suricata-log
cd /opt/suri-agent
# deploy/agent/agent.yaml.example 을 etc/agent.yaml 로 복사한 뒤 수정
```

`agent.yaml`의 핵심 항목은 다음과 같습니다.

```yaml
node_id: gw-home
controller:
  url: wss://suri.example.com/agent/v1/connect
  host_key: "ssh-ed25519 AAAA... suri-controller"
platform:
  profile: docker
  host_root: /host
  firewall: auto        # 호스트의 nft(fw4)를 chroot로 사용
interfaces:
  - name: br-lan
  - name: wan           # PPPoE 라면 pppoe-wan
ips:
  enabled: true
  queues: "0-1"         # CPU 코어 수에 맞춰 조정
suricata:
  instances:
    ids: { log_dir: /var/log/suricata/ids }
    ips: { log_dir: /var/log/suricata/ips }
logs:
  rotation:
    enabled: true       # 플래시/디스크가 가득 차지 않도록
    max_size: 32MiB
    keep: 2
```

## 3. 키 생성과 등록

```sh
docker run --rm -v /opt/suri-agent/etc:/etc/suri-agent ghcr.io/jc-lab/suri-node-agent:latest keygen
# 출력: ssh-ed25519 AAAA... gw-home  → 웹 UI Nodes > Add node 에 붙여넣기
```

## 4. 실행

`deploy/agent/docker-compose.yml`에서 로그 볼륨 경로를 외부 저장 장치로 바꾼 뒤 실행합니다.

```sh
docker compose up -d
docker logs -f suri-node-agent
docker exec suri-node-agent suri-node-agent check
```

## fw4와의 관계

- **IPS 경로**: IPS 모드인 인터페이스의 트래픽은 에이전트가 만든 `table inet suricontroller`에서 NFQUEUE로 보냅니다.
  - forward/input/output 체인이고, priority는 `filter + 10`입니다.
  - fw4가 accept한 트래픽만 Suricata로 갑니다.
- **fw4 재시작**: fw4는 자기 테이블(`inet fw4`)만 다시 씁니다. 에이전트 테이블이 사라지는 경우가 있어도 30초 안에 다시 적용합니다.
- **fail-open**: `ips.fail_open: true`(기본)이면 `bypass` 플래그가 붙습니다. Suricata가 멈춰도 트래픽은 통과합니다.
- **flow offloading**: software/hardware flow offloading이 켜져 있으면 established flow가 netfilter를 우회하므로 Suricata가 보지 못합니다.
  - 에이전트는 이를 감지해 경고로 보고합니다(자동으로 끄지는 않음).
  - IDS/IPS를 쓰는 동안에는 다음처럼 끄는 것을 권장합니다.

```sh
uci set firewall.@defaults[0].flow_offloading='0'
uci set firewall.@defaults[0].flow_offloading_hw='0'
uci commit firewall && /etc/init.d/firewall restart
```

## 로그를 다른 수집기와 함께 쓰기

- 로그 파일 위치와 형식은 `/opt/suri-agent/suricata/suricata.yaml`의 `outputs`와 `logging`에서 정합니다. 이 파일은 사용자 소유입니다.
- 인스턴스별 디렉터리는 `agent.yaml`의 `suricata.instances.*.log_dir`로 정합니다.
- 호스트에 마운트된 로그 디렉터리를 Elastic Agent나 Vector 같은 수집기가 함께 읽어도 됩니다. 에이전트는 파일을 읽기만 합니다.
- 외부 logrotate를 쓴다면 `logs.rotation.enabled: false`로 두고, rotate한 뒤 `docker kill -s HUP suri-node-agent`로 Suricata가 파일을 다시 열게 합니다.
  - 신호는 tini를 거쳐 에이전트에 전달되고, 에이전트가 실행 중인 각 Suricata 인스턴스에 SIGHUP을 보냅니다.
