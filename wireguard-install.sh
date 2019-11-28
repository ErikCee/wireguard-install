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

# Detect public interfaces and pre-fill for the user
SERVER_PUB_NICv4="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
if [[ $SERVER_PUB_NICv4 = "" ]]; then
	SERVER_PUB_NICv6=$(ip -6 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
	if [[ $SERVER_PUB_NICv6 != "" ]]; then
		while true; do
	    read -p "Hmmmmmm.. You seem to be on a IPv6 only network! Would you like to install clat to preform 64XLAT translation to allow IPv4 hardcoded ip addresses to work? [Y/n]:" yn
	    case $yn in
	        [Yy]* ) SERVER_IPV6_ONLY=1
					break
					;;
	        [Nn]* ) echo "IPv4 isn't currently routable... Installing as if it will be in the future."
					break
					;;
	        * ) echo "Please answer yes or no.";;
	    esac
		done
	else
		SERVER_PUB_NICv4=$SERVER_PUB_NICv6
	fi
fi
read -rp "Public IPv4 interface: " -e -i "$SERVER_PUB_NICv4" SERVER_PUB_NICv4

SERVER_PUB_NICv6=$(ip -6 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
if [[ $SERVER_PUB_NICv6 = "" ]]; then
	SERVER_PUB_NICv6=$(ip -6 route  | awk '/via/ { print $5 }'| head -1)
	if [[ $SERVER_PUB_NICv6 = "" ]]; then
		SERVER_PUB_NICv6=$SERVER_PUB_NICv4
	fi
fi
read -rp "Public IPv6 interface: " -e -i "$SERVER_PUB_NICv6" SERVER_PUB_NICv6

SERVER_WG_NIC="wg0"
read -rp "WireGuard interface name: " -e -i "$SERVER_WG_NIC" SERVER_WG_NIC

SERVER_WG_IPV4="10.111.222.1"
read -rp "Server's WireGuard IPv4 " -e -i "$SERVER_WG_IPV4" SERVER_WG_IPV4

echo "Current IPv6 IP's in use:"
ifconfig | awk '/inet6/ { print $2"/"$4 }'
echo ""
SERVER_WG_IPV6="fd42:42:42::1"
read -rp "Server's WireGuard IPv6 " -e -i "$SERVER_WG_IPV6" SERVER_WG_IPV6

SERVER_PORT=1194
read -rp "Server's WireGuard port " -e -i "$SERVER_PORT" SERVER_PORT

CLIENT_AMOUNT=3
read -rp "How many Clients do you want to Generate? " -e -i "$CLIENT_AMOUNT" CLIENT_AMOUNT
# Retrieve system DNS for default
CLIENT_DNS_1="$(grep ^nameserver /etc/resolv.conf | awk '{printf $2}')"

if [[ $(grep ^nameserver /etc/resolv.conf | awk '{printf $2}') != 127.0.0.53 ]] && [[ $(grep ^nameserver /etc/resolv.conf | awk '{printf $2}') != "" ]]; then
	CLIENT_DNS_1=$(grep ^nameserver /etc/resolv.conf | awk '{printf $2}')
else
	CLIENT_DNS_1=1.1.1.1
fi

read -rp "First DNS resolver to use for the client: " -e -i "$CLIENT_DNS_1" CLIENT_DNS_1

if [[ $(grep ^nameserver /etc/resolv.conf | awk '{printf $3}') != 127.0.0.53 ]] && [[ $(grep ^nameserver /etc/resolv.conf | awk '{printf $3}') != "" ]]; then
	CLIENT_DNS_2=$(grep ^nameserver /etc/resolv.conf | awk '{printf $3}')
else
	CLIENT_DNS_2=9.9.9.9
fi
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

if [[ $(command -v wg-quick) = "" ]]; then
	# Install WireGuard tools and module
	if [[ "$OS" = 'ubuntu' ]]; then
		apt install software-properties-common -y
		add-apt-repository ppa:wireguard/wireguard -y
		apt-get update
		if [[ $SERVER_IPV6_ONLY = 1 ]]; then
			apt-get -y install perl-base perl-modules libnet-ip-perl libnet-dns-perl libio-socket-inet6-perl iproute2 iptables tayga git make
			cd /usr/local/src || mkdir -p /usr/local/src ; cd /usr/local/src
			ipv6prefix=$(echo $SERVER_WG_IPV6 | sed -e 's+:.*,++' ) ; ipv6prefix="${ipv6prefix%:*}:"
			echo "clat-v6-addr=${ipv6prefix}aa1" > /etc/clatd.conf
			git clone https://github.com/toreanderson/clatd
			make -C clatd install
		fi
		if [[ $go = 1 ]]; then
			if [[ $(lsmod | grep ^wireguard) != "" ]]; then
				echo "Looks like your Virtual container has wireguard enables in its kernel."
				echo "You can install wireguard-go, and it should use the kernel version, and"
				echo "have the Go version as a backup."
				read -p "Would you like to install wireguard-go? [y/n] " -n 1 -r
				if [[ $REPLY =~ ^[Yy]$ ]]; then
					sudo add-apt-repository ppa:longsleep/golang-backports -y
					sudo apt-get update
					sudo apt-get install -y golang-go
					apt-get -y install make git
					cd /usr/local/src || mkdir -p /usr/local/src ; cd /usr/local/src
					git clone https://git.zx2c4.com/wireguard-go
					cd wireguard-go
					make
					sudo cp wireguard-go /usr/local/bin
				fi
			else
				sudo add-apt-repository ppa:longsleep/golang-backports -y
				sudo apt-get update
				sudo apt-get install -y golang-go
				apt-get -y install make git
				cd /usr/local/src || mkdir -p /usr/local/src ; cd /usr/local/src
				git clone https://git.zx2c4.com/wireguard-go
				cd wireguard-go
				make
				sudo cp wireguard-go /usr/local/bin
			fi
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
fi
if [[ "$OS" = 'ubuntu' ]]; then
	if [[ $SERVER_IPV6_ONLY = 1 ]]; then
		apt-get -y install perl-base perl-modules libnet-ip-perl libnet-dns-perl libio-socket-inet6-perl iproute2 iptables tayga git make
		cd /usr/local/src || mkdir -p /usr/local/src ; cd /usr/local/src
		ipv6prefix=$(echo $SERVER_WG_IPV6 | sed -e 's+:.*,++' ) ; ipv6prefix="${ipv6prefix%:*}:"
		echo "clat-v6-addr=${ipv6prefix}aa1" > /etc/clatd.conf
		git clone https://github.com/toreanderson/clatd
		make -C clatd install
	fi
fi

# Make sure the directory exists (this does not seem the be the case on fedora)
mkdir /etc/wireguard > /dev/null 2>&1

# Generate key pair for the server
SERVER_PRIV_KEY=$(wg genkey)
SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)

# Add pre shared symmetric key to respective files
case "$IS_PRE_SYMM" in
	[yY][eE][sS]|[yY])
		CLIENT_SYMM_PRE_KEY=$( wg genpsk )
		# echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "/etc/wireguard/$SERVER_WG_NIC.conf"
		# echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "$HOME/$SERVER_WG_NIC-client-$post.conf"
		;;
esac
if [[ $SERVER_IPV6_ONLY = 1 ]]; then
	SERVER_PUB_NICv4="clat"
fi
# Add server interface
echo "[Interface]
Address = $SERVER_WG_IPV4/24,$SERVER_WG_IPV6/64
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIV_KEY
PostUp = iptables -t nat -A POSTROUTING -o $SERVER_PUB_NICv4 -j MASQUERADE; iptables -A FORWARD -i $SERVER_PUB_NICv4 -j ACCEPT; iptables -A INPUT -p udp -m udp --dport $SERVER_PORT -j ACCEPT; ip6tables -A FORWARD -i $SERVER_WG_NIC -j ACCEPT; ip6tables -t nat -A POSTROUTING -o $SERVER_PUB_NICv6 -j MASQUERADE; ip6tables -A INPUT -p udp -m udp --dport $SERVER_PORT -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $SERVER_PUB_NICv4 -j MASQUERADE; iptables -D FORWARD -i $SERVER_PUB_NICv4 -j ACCEPT; iptables -D INPUT -p udp -m udp --dport $SERVER_PORT -j ACCEPT; ip6tables -D FORWARD -i $SERVER_WG_NIC -j ACCEPT; ip6tables -t nat -D POSTROUTING -o $SERVER_PUB_NICv6 -j MASQUERADE; ip6tables -D INPUT -p udp -m udp --dport $SERVER_PORT -j ACCEPT

" > "/etc/wireguard/$SERVER_WG_NIC.conf"

ipv6prefix=$(echo $SERVER_WG_IPV6 | sed -e 's+:.*,++' ) ; ipv6prefix="${ipv6prefix%:*}:"
ipv4prefix=$(echo $SERVER_WG_IPV4| sed -e 's+\..*,++' ) ; ipv4prefix="${ipv4prefix%.*}."
for (( count = 0; count < CLIENT_AMOUNT; count++ )); do
	startnum=$(echo $SERVER_WG_IPV4 | sed -e 's+.*\.++')
	post=$(( count + startnum + 1 ))
	# Generate key pair for the server
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)

	CLIENT_WG_IPV4=$ipv4prefix$post
	CLIENT_WG_IPV6=$ipv6prefix$post
	# Add the client as a peer to the server
	echo "[Peer]
PublicKey = $CLIENT_PUB_KEY
AllowedIPs = $CLIENT_WG_IPV4/32,$CLIENT_WG_IPV6/128" >> "/etc/wireguard/$SERVER_WG_NIC.conf"
	if [[ $CLIENT_SYMM_PRE_KEY != "" ]]; then
		echo "PresharedKey = $CLIENT_SYMM_PRE_KEY
" >> "/etc/wireguard/$SERVER_WG_NIC.conf"
	else
		echo "
" >> "/etc/wireguard/$SERVER_WG_NIC.conf"
	fi

	# Create client file with interface
	echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = $CLIENT_WG_IPV4/24,$CLIENT_WG_IPV6/64
DNS = $CLIENT_DNS_1,$CLIENT_DNS_2
" > "$HOME/$SERVER_WG_NIC-client-$post.conf"
	# Add the server as a peer to the client
	echo "[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0" >> "$HOME/$SERVER_WG_NIC-client-$post.conf"
	if [[ $CLIENT_SYMM_PRE_KEY != "" ]]; then
		echo "PresharedKey = $CLIENT_SYMM_PRE_KEY
" >> "$HOME/$SERVER_WG_NIC-client-$post.conf"
	else
		echo "
" >> "$HOME/$SERVER_WG_NIC-client-$post.conf"
	fi
done

chmod 600 -R /etc/wireguard/

# Enable routing on the server
echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" > /etc/sysctl.d/wg.conf

sysctl --system

systemctl start "wg-quick@$SERVER_WG_NIC"
systemctl enable "wg-quick@$SERVER_WG_NIC"
if [[ $SERVER_IPV6_ONLY = 1 ]]; then
	systemctl start clatd
	systemctl enable clatd
fi

if [[ $go = 1 ]]; then
	systemctl stop "wg-quick@$SERVER_WG_NIC"
	sed -i '/RETRIES=infinity/{n;s/.*/Environment=WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1/}' /lib/systemd/system/wg-quick@.service
	systemctl daemon-reload
	echo "export WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1" >> ~/.profile
	echo "export WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1" >> ~/.bashrc
	systemctl start "wg-quick@$SERVER_WG_NIC"
fi
