# Introduction

`net-my-filter` is a very simple bash script to generate some basic firewall rules with nftables.

There are two types of server rules:
1. Server with a public-facing IP address with `sshd` being the only service which is open to the internet. All incoming traffic is blocked, all outgoing is allowed. Incoming traffic is logged to `dmesg`.
2. Server with a public-facing IP address with `sshd` and WireGuard server open to the internet. Masquerading rules added for Wireguard server, port 53 is also allowed for Wireguard interface. All incoming traffic is blocked, all outgoing is allowed. Incoming traffic is logged to `dmesg`.

# Usage

The script may evolve with time, though at the moment it's quite simple. We are not going to pipe to bash and will instead clone the repo.

```bash
$ git clone https://github.com/SirToffski/net-my-filter.git # (1) clone the repo
$ cd net-my-filter # (2) cd into the cloned repo
$ sudo bash nf_gen.sh [OPTION]
```
```
  Usage: gen_nf_tables.sh [OPTION]

  -n, --novpn        writes nftables for a machine without a VPN server
  -v, --vpn          writes nftables for a machine hosting a VPN server
  -h, --help         print this message
```
