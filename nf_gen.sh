#!/usr/bin/env bash

# Rules inspired by
# https://xdeb.org/post/2019/09/26/setting-up-a-server-firewall-with-nftables-that-support-wireguard-vpn/

check_root() {
  if [ "$EUID" -ne 0 ]; then
    printf %s\\n "Please run the script as root."
    exit 1
  fi
}

backup_existing_nf() {
  if [[ -f /etc/nftables.conf ]]; then
    mv /etc/nftables.conf /etc/nftables.conf.bak
  fi
}

set_server_vars() {
  wan_iface="eth0"
  ssh_port="22"
  ## IP blacklist from Talos intelligence @ https://talosintelligence.com/
  ip_blacklist="$(curl "https://talos-intelligence-site.s3.amazonaws.com/production/document_files/files/000/089/396/original/ip_filter.blf" | sed ':a;N;$!ba;s/\n/,/g')"
  allowed_udp="58172"
  vpn_iface="wg0"
  vpn_subnet="10.20.30.0/27"
}

server_no_vpn() {
  printf %\\n "#!/usr/bin/nft -f

# Start by flushing all the rules.
flush ruleset

# Defining variables is easy in nftables scripts.
define wan = $wan_iface

# Setting up a table, simple firewalls will only need one table but there can be multiple.
# The \"init\" say that this table will handle both ipv4 (ip) and ipv6 (ip6).
# The name is \"firewall\" you can name it anything you like.
table inet firewall {
  # Sets are dictionaries and maps of ports, addresses etc.
  # These can then easily be used in the rules.
  # Sets can be named whatever you like.
  # TCP ports to allow, here we add ssh, http and https.
  set tcp_accepted {
    # The \"inet_service\" are for tcp/udp ports and \"flags interval\" allows to set intervals, see the mosh ports below.
    type inet_service; flags interval;
    elements = {
      $ssh_port
    }
  }
  # UDP ports to allow, here we add a port for WireGuard and mosh.
  set udp_accepted {
    type inet_service; flags interval;
    elements = {

    }
  }
  # List of ipv4 addresses to blacklist.
  set blacklist_v4 {
    # The \"ipv4_addr\" are for ipv4 addresses and \"flags interval\" allows to set intervals.
    type ipv4_addr; flags interval;
    elements = {
      $ip_blacklist
    }
  }

  # The first chain, can be named anything you like.
  chain incoming {
    # This line set what traffic the chain will handle, the priority and default policy.
    # The priority comes in when you in another table have a chain set to \"hook input\" and want to specify in what order they should run.
    # Use a semicolon to separate multiple commands on one row.
    type filter hook input priority 0; policy drop;

    # Limit ping requests.
    ip protocol icmp icmp type echo-request limit rate over 1/second burst 5 packets drop
    ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate over 1/second burst 5 packets drop

    # OBS! Rules with \"limit\" need to be put before rules accepting \"established\" connections.
    # Allow all incmming established and related traffic. Drop invalid traffic.
    ct state established,related accept
    ct state invalid drop

    # Allow loopback.
    # Interfaces can by set with \"iif\" or \"iifname\" (oif/oifname). If the interface can come and go use \"iifname\", otherwise use \"iif\" since it performs better.
    iifname lo accept

    # Blacklist bad addresses.
    # This is how sets are used in rules, a \"@\" and the name of the set.
    # In nftable you need to add a counter statement to have the rule count matches.
    # Only add counter if you need it, it has a small performance hit. I add it to
    # rules I'm unsure how useful/accurate they are.
    ip saddr @blacklist_v4 counter drop

    # Drop all fragments.
    ip frag-off & 0x1fff != 0 counter drop

    # Force SYN checks.
    tcp flags & (fin|syn|rst|ack) != syn ct state new counter drop

    # Drop XMAS packets.
    tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst|psh|ack|urg counter drop

    # Drop NULL packets.
    tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 counter drop

    # Allow certain inbound ICMP types (ping, traceroute).
    # With these allowed you are a good network citizen.
    ip protocol icmp icmp type { destination-unreachable, echo-reply, echo-request, source-quench, time-exceeded } accept
    # Without the nd-* ones ipv6 will not work.
    ip6 nexthdr icmpv6 icmpv6 type { destination-unreachable, echo-reply, echo-request, nd-neighbor-solicit,  nd-router-advert, nd-neighbor-advert, packet-too-big, parameter-problem, time-exceeded } accept

    # Allow needed tcp and udp ports.
    iifname \$wan tcp dport @tcp_accepted ct state new accept
    iifname \$wan udp dport @udp_accepted ct state new accept

  }

  chain forwarding {
    type filter hook forward priority 0; policy drop;
  }

  chain outgoing {
    type filter hook output priority 0; policy drop;

    # Allow all outgoing traffic. Drop invalid traffic.
    # I believe settings \"policy accept\" would be the same but I prefer explicit rules.
    ct state new,established,related accept
    ct state invalid drop
  }
}

table ip router {
    # Both need to be set even when one is empty.
    chain prerouting {
        type nat hook prerouting priority 0;
    }
    chain postrouting {
        type nat hook postrouting priority 100;

    }
}" | tee /etc/nftables.conf >/dev/null
}

server_with_vpn() {
  printf %\\n "#!/usr/bin/nft -f

# Start by flushing all the rules.
flush ruleset

# Defining variables is easy in nftables scripts.
define wan = $wan_iface
define vpn = $vpn_iface
define vpn_net = $vpn_subnet

# Setting up a table, simple firewalls will only need one table but there can be multiple.
# The \"init\" say that this table will handle both ipv4 (ip) and ipv6 (ip6).
# The name is \"firewall\" you can name it anything you like.
table inet firewall {
  # Sets are dictionaries and maps of ports, addresses etc.
  # These can then easily be used in the rules.
  # Sets can be named whatever you like.
  # TCP ports to allow, here we add ssh, http and https.
  set tcp_accepted {
    # The \"inet_service\" are for tcp/udp ports and \"flags interval\" allows to set intervals, see the mosh ports below.
    type inet_service; flags interval;
    elements = {
      $ssh_port
    }
  }
  # UDP ports to allow, here we add a port for WireGuard and mosh.
  set udp_accepted {
    type inet_service; flags interval;
    elements = {
      $allowed_udp
    }
  }
  # List of ipv4 addresses to blacklist.
  set blacklist_v4 {
    # The \"ipv4_addr\" are for ipv4 addresses and \"flags interval\" allows to set intervals.
    type ipv4_addr; flags interval;
    elements = {
      $ip_blacklist
    }
  }

  # The first chain, can be named anything you like.
  chain incoming {
    # This line set what traffic the chain will handle, the priority and default policy.
    # The priority comes in when you in another table have a chain set to \"hook input\" and want to specify in what order they should run.
    # Use a semicolon to separate multiple commands on one row.
    type filter hook input priority 0; policy drop;

    # Limit ping requests.
    ip protocol icmp icmp type echo-request limit rate over 1/second burst 5 packets drop
    ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate over 1/second burst 5 packets drop

    # OBS! Rules with \"limit\" need to be put before rules accepting \"established\" connections.
    # Allow all incmming established and related traffic. Drop invalid traffic.
    ct state established,related accept
    ct state invalid drop

    # Allow loopback.
    # Interfaces can by set with \"iif\" or \"iifname\" (oif/oifname). If the interface can come and go use \"iifname\", otherwise use \"iif\" since it performs better.
    iifname lo accept

    # Blacklist bad addresses.
    # This is how sets are used in rules, a \"@\" and the name of the set.
    # In nftable you need to add a counter statement to have the rule count matches.
    # Only add counter if you need it, it has a small performance hit. I add it to
    # rules I'm unsure how useful/accurate they are.
    ip saddr @blacklist_v4 counter drop

    # Drop all fragments.
    ip frag-off & 0x1fff != 0 counter drop

    # Force SYN checks.
    tcp flags & (fin|syn|rst|ack) != syn ct state new counter drop

    # Drop XMAS packets.
    tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst|psh|ack|urg counter drop

    # Drop NULL packets.
    tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 counter drop

    # Allow certain inbound ICMP types (ping, traceroute).
    # With these allowed you are a good network citizen.
    ip protocol icmp icmp type { destination-unreachable, echo-reply, echo-request, source-quench, time-exceeded } accept
    # Without the nd-* ones ipv6 will not work.
    ip6 nexthdr icmpv6 icmpv6 type { destination-unreachable, echo-reply, echo-request, nd-neighbor-solicit,  nd-router-advert, nd-neighbor-advert, packet-too-big, parameter-problem, time-exceeded } accept

    # Allow needed tcp and udp ports.
    iifname \$wan tcp dport @tcp_accepted ct state new accept
    iifname \$wan udp dport @udp_accepted ct state new accept

    # Allow WireGuard clients to access DNS and services.
    iifname \$vpn udp dport 53 ct state new accept
    iifname \$vpn tcp dport @tcp_accepted ct state new accept
    iifname \$vpn udp dport @udp_accepted ct state new accept

  }

  chain forwarding {
    type filter hook forward priority 0; policy drop;

    # Forward all established and related traffic. Drop invalid traffic.
    ct state established,related accept
    ct state invalid drop

    # Forward WireGuard traffic.
    # Allow WireGuard traffic to access the internet via wan.
    iifname \$vpn oifname \$wan ct state new accept
  }

  chain outgoing {
    type filter hook output priority 0; policy drop;

    # Allow all outgoing traffic. Drop invalid traffic.
    # I believe settings \"policy accept\" would be the same but I prefer explicit rules.
    ct state new,established,related accept
    ct state invalid drop
  }
}

table ip router {
    # Both need to be set even when one is empty.
    chain prerouting {
        type nat hook prerouting priority 0;
    }
    chain postrouting {
        type nat hook postrouting priority 100;

        # Masquerade WireGuard traffic.
        # All WireGuard traffic will look like it comes from the servers IP address.
        oifname \$wan ip saddr \$vpn_subnet masquerade

    }
}" | tee /etc/nftables.conf >/dev/null
}

main() {
  if [ $# -gt 0 ]; then

    case $1 in
      --novpn | -n)
        check_root
        printf %b\\n ":: Backing up existing nftables"
        sleep 1
        backup_existing_nf
        printf %b\\n ":: Writing non-VPN server config to /etc/nftables.conf"
        set_server_vars
        sleep 1
        server_no_vpn
        printf %b\\n ":: Done!"
        ;;
      --vpn | -v)
        check_root
        printf %b\\n ":: Backing up existing nftables"
        sleep 1
        backup_existing_nf
        printf %b\\n ":: Writing non-VPN server config to /etc/nftables.conf"
        set_server_vars
        sleep 1
        server_with_vpn
        printf %b\\n ":: Done!"
        ;;
      --help | -h)
        printf %b\\n "\nNo argumets were passed.\n
  Usage: gen_nf_tables.sh [OPTION]\n
  -n, --novpn        writes nftables for a machine without a VPN server
  -v, --vpn          writes nftables for a machine hosting a VPN server
  -h, --help         print this message" && exit
        ;;
    esac
  else
    printf %b\\n "\nNo argumets were passed.\n
  Usage: gen_nf_tables.sh [OPTION]\n
  -n, --novpn        writes nftables for a machine without a VPN server
  -v, --vpn          writes nftables for a machine hosting a VPN server
  -h, --help         print this message" && exit
  fi
}

main "$@"
