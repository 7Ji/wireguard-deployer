# Systemd-networkd wireguard deployer
A tool to generate WireGuard configs and keys for systemd-networkd and pack them into .tar with correct permissions and ownerships that are easily deployable.

Everything can be configured on a centralized host in a centralized config file, and almost any common network topologies are supported.

## Build

```
cargo build --release
```

The ouput binary would be `target/release/sd-networkd-wg-deploy`

## Usage
```
./sd-networkd-wg-deploy [config file] [to-be-deployed dir]
```
in which:
- `[config file]` is the path to a .yaml file that meets the format documented in the following section
- `[to be deployed dir]` is the path to a (possibly already existing) folder that keys and configs would be stored in. Keys are always lazily generated while configs are always freshly generated, so you can place your existing keys in corresponding path to only let the deployer generate configs.

e.g.:
```
./sd-networkd-wg-deploy example.conf.yaml example.d
```

The result to-be-deployed dir structure would be like this:
```
example.d
├── configs
│   ├── hostA
│   │   ├── 30-wireguard.netdev
│   │   ├── 40-wireguard.network
│   │   └── keys
│   │       └── wg
│   │           ├── pre-shared-hostA-siteC
│   │           ├── pre-shared-hostA-vmA
│   │           ├── pre-shared-hostA-vmB
│   │           ├── pre-shared-hostA-vmC
│   │           └── private-hostA
│   ├── hostA.tar
│   ├── hostB
│   │   ├── 30-wireguard.netdev
│   │   ├── 40-wireguard.network
│   │   └── keys
│   │       └── wg
│   │           ├── pre-shared-hostB-siteC
│   │           └── private-hostB
│   ├── hostB.tar
│   ├── hostC
│   │   ├── 30-wireguard.netdev
│   │   ├── 40-wireguard.network
│   │   └── keys
│   │       └── wg
│   │           ├── pre-shared-hostC-siteC
│   │           └── private-hostC
│   ├── hostC.tar
│   ├── hostD
│   │   ├── 30-wireguard.netdev
│   │   ├── 40-wireguard.network
│   │   └── keys
│   │       └── wg
│   │           ├── pre-shared-hostD-siteC
│   │           └── private-hostD
│   ├── hostD.tar
│   ├── hostE
│   │   ├── 30-wireguard.netdev
│   │   ├── 40-wireguard.network
│   │   └── keys
│   │       └── wg
│   │           ├── pre-shared-hostE-siteC
│   │           └── private-hostE
│   ├── hostE.tar
│   ├── siteA
│   │   ├── 30-wireguard.netdev
│   │   ├── 40-wireguard.network
│   │   └── keys
│   │       └── wg
│   │           ├── pre-shared-siteA-siteB
│   │           ├── pre-shared-siteA-siteC
│   │           └── private-siteA
│   ├── siteA.tar
│   ├── siteB
│   │   ├── 30-wireguard.netdev
│   │   ├── 40-wireguard.network
│   │   └── keys
│   │       └── wg
│   │           ├── pre-shared-siteA-siteB
│   │           ├── pre-shared-siteB-siteC
│   │           └── private-siteB
│   ├── siteB.tar
│   ├── siteC
│   │   ├── 30-wireguard.netdev
│   │   ├── 40-wireguard.network
│   │   └── keys
│   │       └── wg
│   │           ├── pre-shared-hostA-siteC
│   │           ├── pre-shared-hostB-siteC
│   │           ├── pre-shared-hostC-siteC
│   │           ├── pre-shared-hostD-siteC
│   │           ├── pre-shared-hostE-siteC
│   │           ├── pre-shared-siteA-siteC
│   │           ├── pre-shared-siteB-siteC
│   │           └── private-siteC
│   ├── siteC.tar
│   ├── vmA
│   │   ├── 30-wireguard.netdev
│   │   ├── 40-wireguard.network
│   │   └── keys
│   │       └── wg
│   │           ├── pre-shared-hostA-vmA
│   │           ├── pre-shared-vmA-vmB
│   │           ├── pre-shared-vmA-vmC
│   │           └── private-vmA
│   ├── vmA.tar
│   ├── vmB
│   │   ├── 30-wireguard.netdev
│   │   ├── 40-wireguard.network
│   │   └── keys
│   │       └── wg
│   │           ├── pre-shared-hostA-vmB
│   │           ├── pre-shared-vmA-vmB
│   │           ├── pre-shared-vmB-vmC
│   │           └── private-vmB
│   ├── vmB.tar
│   ├── vmC
│   │   ├── 30-wireguard.netdev
│   │   ├── 40-wireguard.network
│   │   └── keys
│   │       └── wg
│   │           ├── pre-shared-hostA-vmC
│   │           ├── pre-shared-vmA-vmC
│   │           ├── pre-shared-vmB-vmC
│   │           └── private-vmC
│   └── vmC.tar
└── keys
    ├── pre-shared-hostA-siteC
    ├── pre-shared-hostA-vmA
    ├── pre-shared-hostA-vmB
    ├── pre-shared-hostA-vmC
    ├── pre-shared-hostB-siteC
    ├── pre-shared-hostC-siteC
    ├── pre-shared-hostD-siteC
    ├── pre-shared-hostE-siteC
    ├── pre-shared-siteA-siteB
    ├── pre-shared-siteA-siteC
    ├── pre-shared-siteB-siteC
    ├── pre-shared-vmA-vmB
    ├── pre-shared-vmA-vmC
    ├── pre-shared-vmB-vmC
    ├── private-hostA
    ├── private-hostB
    ├── private-hostC
    ├── private-hostD
    ├── private-hostE
    ├── private-siteA
    ├── private-siteB
    ├── private-siteC
    ├── private-vmA
    ├── private-vmB
    └── private-vmC
```
In which the .tar file already contains a sane permissioon and ownership setup:
```
> tar -tvf example.d/configs/mi3.tar
drwxr-x--- root/systemd-network 0 2024-06-10 12:59 keys
drwxr-x--- root/systemd-network 0 2024-06-10 12:59 keys/wg
-rw-r----- root/systemd-network 44 2024-06-10 12:59 keys/wg/private-mi3
-rw-r----- root/systemd-network 44 2024-06-10 12:59 keys/wg/pre-shared-hk1-mi3
-rw-r--r-- root/root           706 2024-06-10 12:59 30-wireguard.netdev
-rw-r--r-- root/root           327 2024-06-10 12:59 40-wireguard.network
```
Consider plain folders as quick lookup reference. It's recommended to use the .tar files to actually deploy your configs and keys so you won't need to `chown` and `chmod` by yourself.

You can deploy it however as you like. For a quick example, use the helper script to deploy the config to SSH remotes:
```
./script/deploy-to-ssh.sh example.d hk1 l3a cm2 r33 mi3 v7j vbt vdb fuo:fuo.fuckblizzard.com pdh:pdh.fuckblizzard.com
```
On a host where the tar file is already available (e.g. on current host), you can deploy it as follows:
```
sudo tar -C /etc/systemd/network -xvf example.d/configs/rz5.tar
sudo systemctl restart systemd-networkd
```

## Config
The config format is simple yet powerful, it's defined as follows:
```yaml
psk: [bool, global pre-shared keys option, e.g. true]
iface: [string, global interface name, e.g. wg0]
netdev: [string, global systemd.netdev name without suffix, e.g. 30-wireguard]
network: [string, global systemd.network name without suffix, e.g. 40-wireguard]
mask: [unsigned integer, global wireguard network subnet netmask suffix, e.g. 24]
peers: [map of peer, top level peers]
```
In which, a `peer` map is defined as follows:
```yaml
[string, unique peer name, e.g. siteA]:
  iface: [string, optional, peer interface name, if not set then global iface would be used, e.g. wg1]
  netdev: [string, optional, peer systemd.netdev name without suffix, if not set then global netdev would be used, e.g. 50-wireguard-personal]
  network: [string, optional, peer systemd.network name without suffix, if not set then global network would be used, e.g. 60-wireguard-personal]
  ip: [string, wireguard network ip without subnet netmask suffix, e.g. 192.168.77.2]
  endpoint: [endpoint definition, optional, either a plain string, e.g. siteA.host.com, or advanced endpoint definition]
  forward: [list of IP ranges, optional, non-wireguard subnets this peer can forward wireguard traffic into]
  children: [map of peer, optional, peers using this peer as "router" to talk to the wireguard network]
  direct: [list of peer names, optional, selective peers in current layer that this peer is able to connect to directly, if not set then assuming all, if set to empty then none and only able to connect to parent (if existing) / children]
```
In which, advanced endpoint definition is as follows:
```yaml
endpoint:
  parent: [string, endpoint address that this peer's parent shall use to connect to this peer]
  neighbor: [string, endpoint address that this peer's neighbors shall use to connect to this peer]
  child: [string, endpoint address that this peer's children shall use to connect to this peer]
```
The above may look complicated but it's in fact very simple, e.g. a simple full mesh setup could be defined as follows:
```yaml
psk: true
iface: wg0
netdev: 30-wireguard
network: 40-wireguard
mask: 24
peers:
  hostA:
    ip: 192.168.66.2
    endpoint: hostA.example.com
  hostB:
    ip: 192.168.66.3
    endpoint: hostB.example.com
  hostC:
    ip: 192.168.66.4
    endpoint: hostC.example.com
  ....
```
**(global options would be omitted in following examples)**

A simple star setup could be defined as follows, (i.e. single router/server + multiple clients), note each "client" can only access the parent "server", and to access other clients the traffic need to go through the parent.
```yaml
peers:
  server:
    ip: 192.168.66.1
    endpoint: server.example.com
    children:
      clientA:
        ip: 192.168.66.2
        endpoint: clientA.example.com
        direct: []
      clientB:
        ip: 192.168.66.3
        endpoint: clientB.example.com
        direct: []
      clientC:
        ip: 192.168.66.4
        endpoint: clientC.example.com
        direct: []
        ....
```
A single layer star + mesh setup could be defined as follows, where "clients" in a "star" network can access each other just like in a full-mesh network. 
```yaml
peers:
  server:
    ip: 192.168.66.1
    endpoint: server.example.com
    children:
      clientA:
        ip: 192.168.66.2
        endpoint: clientA.example.com
      clientB:
        ip: 192.168.66.3
        endpoint: clientB.example.com
      clientC:
        ip: 192.168.66.4
        endpoint: clientC.example.com
        ....
```
A in-wireguard full mesh where each peer also forwards their non-wireguard traffic into the network, i.e. a common site + site VPN setup
```yaml
peers:
  siteA:
    ip: 192.168.66.2
    endpoint: siteA.example.com
    forward:
      - 192.168.100.0/24
      - 10.19.0.0/16
  siteB:
    ip: 192.168.66.3
    endpoint: siteB.example.com
    forward:
      - 192.168.102.0/24
      - fdb5:c701:19a6::/48
  siteC:
    ip: 192.168.66.4
    endpoint: siteC.example.com
    forward:
      - 192.168.105.0/24
      - fd60:c3e0:a2d7::/48
  ....
```
A multi layer full mesh + star hybrid setup, where siteA + siteB + siteC + siteD function all as "VPN site", but traffic behind siteD need to go through it in wireguard, instead of forwarding the lan traffic directly, this is useful if the network behind siteD is not trustworthy (i.e. public network for a personal wireguard network). An example traffic line with the following config is `192.168.100.23 -> siteA (192.168.100.1 + 192.168.66.2) -> siteD (192.168.66.5) -> hostA (192.168.66.51 + 172.16.14.1) -> 172.16.14.14`
```yaml
peers:
  siteA:
    ip: 192.168.66.2
    endpoint: siteA.example.com
    forward:
      - 192.168.100.0/24
      - 10.19.0.0/16
  siteB:
    ip: 192.168.66.3
    endpoint: siteB.example.com
    forward:
      - 192.168.102.0/24
      - fdb5:c701:19a6::/48
  siteC:
    ip: 192.168.66.4
    endpoint: siteC.example.com
    forward:
      - 192.168.105.0/24
      - fd60:c3e0:a2d7::/48
  siteD:
    ip: 192.168.66.5
    endpoint:
      neighbor: siteD.example.com
      child: siteD.lan
    children:
      hostA:
        ip: 192.168.66.51
        endpoint: hostA.lan
        forward:
          - 172.16.14.0/24
          - 172.16.16.0/24
      hostB:
        ip: 192.168.66.52
        endpoint: hostB.lan
      hostC:
        ip: 192.168.66.53
        endpoint: hostC.lan
  ....
```

## See also
[sd-networkd-wg-ddns](https://github.com/7Ji/sd-networkd-wg-ddns), systemd-networkd wireguard netdev endpoints DynDNS updater. Use it to actively monitor for wireguard peers with endpoints that're set up using domain name instead of plain IPs, and update them in case DNS record updated.

## License
**sd-networkd-wg-deployer**, to generate easily deployable WireGuard configs and keys for systemd-networkd

Copyright (C) 2024-present Guoxin "7Ji" Pu

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.