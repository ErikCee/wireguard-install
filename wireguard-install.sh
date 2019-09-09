#!/bin/bash

if [ "$EUID" -ne 0 ]; then
	echo "You need to run this script as root"
	exit 1
fi

if [ "$(systemd-detect-virt)" == "openvz" ]; then
	echo "OpenVZ is not supported"
	go=1
fi

if [ "$(systemd-detect-virt)" == "lxc" ]; then
	echo "LXC is Beta, and only tested on Ubuntu 18.04."
	echo ""
	go=1
fi

# Check OS version
if [[ -e /etc/debian_version ]]; then
	source /etc/os-release
	OS=$ID # debian or ubuntu
elif [[ -e /etc/fedora-release ]]; then
	OS=fedora
elif [[ -e /etc/centos-release ]]; then
	OS=centos
elif [[ -e /etc/arch-release ]]; then
	OS=arch
else
	echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS or Arch Linux system"
	exit 1
fi

# Detect public IPv4 address and pre-fill for the user
SERVER_PUB_IPV4=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [[ $SERVER_PUB_IPV4 = "" ]]; then
	SERVER_PUB_IPV4=$(ifconfig | grep "inet6 2"|  awk '{print $2}')
fi

read -rp "IPv4 or IPv6 public address: " -e -i "$SERVER_PUB_IPV4" SERVER_PUB_IP

# Detect public interface and pre-fill for the user
SERVER_PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
if [[ $SERVER_PUB_NIC = "" ]]; then
	SERVER_PUB_NIC=$(ip -6 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
fi
read -rp "Public interface: " -e -i "$SERVER_PUB_NIC" SERVER_PUB_NIC

SERVER_WG_NIC="wg0"
read -rp "WireGuard interface name: " -e -i "$SERVER_WG_NIC" SERVER_WG_NIC

SERVER_WG_IPV4="10.111.222.1"
read -rp "Server's WireGuard IPv4 " -e -i "$SERVER_WG_IPV4" SERVER_WG_IPV4

SERVER_WG_IPV6="fd42:42:42::1"
read -rp "Server's WireGuard IPv6 " -e -i "$SERVER_WG_IPV6" SERVER_WG_IPV6

SERVER_PORT=1194
read -rp "Server's WireGuard port " -e -i "$SERVER_PORT" SERVER_PORT

CLIENT_WG_IPV4="${SERVER_WG_IPV4%.*}.2"
read -rp "Client's WireGuard IPv4 " -e -i "$CLIENT_WG_IPV4" CLIENT_WG_IPV4

CLIENT_WG_IPV6="${SERVER_WG_IPV6%:*}:2"
read -rp "Client's WireGuard IPv6 " -e -i "$CLIENT_WG_IPV6" CLIENT_WG_IPV6

# Retrieve system DNS for default
CLIENT_DNS_1="$(grep ^nameserver /etc/resolv.conf | awk '{printf $2}')"
read -rp "First DNS resolver to use for the client: " -e -i "$CLIENT_DNS_1" CLIENT_DNS_1

CLIENT_DNS_2="$(grep ^nameserver /etc/resolv.conf | awk '{printf $3}')"
read -rp "Second DNS resolver to use for the client: " -e -i "$CLIENT_DNS_2" CLIENT_DNS_2

# Ask for pre-shared symmetric key
IS_PRE_SYMM="y"
read -rp "Want to use pre-shared symmetric key? [Y/n]: " -e -i "$IS_PRE_SYMM" IS_PRE_SYMM

if [[ $SERVER_PUB_IP =~ .*:.* ]]
then
  echo "IPv6 Detected"
  ENDPOINT="[$SERVER_PUB_IP]:$SERVER_PORT"
else
  echo "IPv4 Detected"
  ENDPOINT="$SERVER_PUB_IP:$SERVER_PORT"
fi

# Install WireGuard tools and module
if [[ "$OS" = 'ubuntu' ]]; then
	apt install software-properties-common -y
	add-apt-repository ppa:wireguard/wireguard -y
	apt-get update
	if [[ $go = 1 ]]; then
		sudo add-apt-repository ppa:longsleep/golang-backports
		sudo apt-get update
		sudo apt-get install -y golang-go
		apt-get -y install make git
		cd /usr/local/src || mkdir -p /usr/local/src ; cd /usr/local/src 
		git clone https://git.zx2c4.com/wireguard-go
		cd wireguard-go
		make
		sudo cp wireguard-go /usr/local/bin
		apt-get -y install wireguard-tools --no-install-recommends
	else
		apt-get -y install wireguard
	fi
elif [[ "$OS" = 'debian' ]]; then
	echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
	printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
	apt update
	apt install wireguard
elif [[ "$OS" = 'fedora' ]]; then
	dnf copr enable jdoss/wireguard
	dnf install wireguard-dkms wireguard-tools
elif [[ "$OS" = 'centos' ]]; then
	curl -Lo /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
	yum install epel-release
	yum install wireguard-dkms wireguard-tools
elif [[ "$OS" = 'arch' ]]; then
	pacman -S wireguard-tools
fi

# Make sure the directory exists (this does not seem the be the case on fedora)
mkdir /etc/wireguard > /dev/null 2>&1

# Generate key pair for the server
SERVER_PRIV_KEY=$(wg genkey)
SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)

# Generate key pair for the server
CLIENT_PRIV_KEY=$(wg genkey)
CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)

# Add server interface
echo "[Interface]
Address = $SERVER_WG_IPV4/24,$SERVER_WG_IPV6/64
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIV_KEY
PostUp = iptables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; iptables -A FORWARD -i $SERVER_WG_NIC -j ACCEPT; iptables -A INPUT -p udp -m udp --dport $SERVER_PORT -j ACCEPT; ip6tables -A FORWARD -i $SERVER_WG_NIC -j ACCEPT; ip6tables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -A INPUT -p udp -m udp --dport $SERVER_PORT -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; iptables -D FORWARD -i $SERVER_WG_NIC -j ACCEPT; iptables -D INPUT -p udp -m udp --dport $SERVER_PORT -j ACCEPT; ip6tables -D FORWARD -i $SERVER_WG_NIC -j ACCEPT; ip6tables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -D INPUT -p udp -m udp --dport $SERVER_PORT -j ACCEPT
" > "/etc/wireguard/$SERVER_WG_NIC.conf"

# Add the client as a peer to the server
echo "[Peer]
PublicKey = $CLIENT_PUB_KEY
AllowedIPs = $CLIENT_WG_IPV4/32,$CLIENT_WG_IPV6/128" >> "/etc/wireguard/$SERVER_WG_NIC.conf"

# Create client file with interface
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = $CLIENT_WG_IPV4/24,$CLIENT_WG_IPV6/64
DNS = $CLIENT_DNS_1,$CLIENT_DNS_2" > "$HOME/$SERVER_WG_NIC-client.conf"

# Add the server as a peer to the client
echo "[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0" >> "$HOME/$SERVER_WG_NIC-client.conf"

# Add pre shared symmetric key to respective files
case "$IS_PRE_SYMM" in
	[yY][eE][sS]|[yY])
		CLIENT_SYMM_PRE_KEY=$( wg genpsk )
		echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "/etc/wireguard/$SERVER_WG_NIC.conf"
		echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "$HOME/$SERVER_WG_NIC-client.conf"
		;;
esac

chmod 600 -R /etc/wireguard/

# Enable routing on the server
echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" > /etc/sysctl.d/wg.conf

sysctl --system

systemctl start "wg-quick@$SERVER_WG_NIC"
systemctl enable "wg-quick@$SERVER_WG_NIC"

if [[ $go = 1 ]]; then
	systemctl stop "wg-quick@$SERVER_WG_NIC"
	sed -i '/RETRIES=infinity/{n;s/.*/Environment=WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1/}' /lib/systemd/system/wg-quick@.service
	systemctl daemon-reload
	echo "export WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1" >> ~/.profile
	echo "export WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1" >> ~/.bashrc
	systemctl start "wg-quick@$SERVER_WG_NIC"
fi
