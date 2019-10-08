#!/bin/bash
if [[ $1 = "" ]] || [ ! -e "$1" ]; then
	echo "USAGE:	$(basename "$0") <Highest Client Prefered>"
	exit 1
else
	source="$1"
fi
# cd "$HOME" || exit
SERVER_WG_NIC="$(basename "$source")"
if [ ! -e "/etc/wireguard/${SERVER_WG_NIC%%-*}.conf" ]; then
	SERVER_WG_NIC="wg0"
	read -rp "WireGuard interface name: " -e -i "$SERVER_WG_NIC" SERVER_WG_NIC
else
	SERVER_WG_NIC=${SERVER_WG_NIC%%-*}
fi
WG_START=${source/*-}
WG_START=$(( ${WG_START%.*} + 1 ))
read -rp "WireGuard Client aditional IP start: " -e -i "$WG_START" WG_START
WG_END=$(( WG_START + 5 ))
read -rp "WireGuard Client aditional IP end(Default makes 5 Configs): " -e -i "$WG_END" WG_END
if [ -e /etc/wireguard/"$SERVER_WG_NIC".conf ]; then
	echo "Using /etc/wireguard/$SERVER_WG_NIC.conf"
else
	echo "$SERVER_WG_NIC doesn't seem to exist. Here is what is in your /etc/wireguard folder..."
	ls -1 /etc/wireguard
	exit 1
fi
cp /etc/wireguard/"$SERVER_WG_NIC".conf /etc/wireguard/"$SERVER_WG_NIC.conf-$(date '+%Y-%d-%m %H%M').bak"

ipv6prefix=$(grep Address "$source" | awk '{ print $3 }' | sed -e 's+.*,++' ) ; ipv6prefix="${ipv6prefix%:*}:"
ipv4prefix=$(grep Address "$source" | awk '{ print $3 }' ) ; ipv4prefix="${ipv4prefix%.*}."
echo "Stopping Wireguard on interface $SERVER_WG_NIC to make changes"
wg-quick down $SERVER_WG_NIC
for ((i=WG_START; i<=WG_END; i++)) ; do
	private=$(wg genkey)
	public=$(echo "$private" | wg pubkey)
	sed "2 cPrivateKey = $private" "$source" > "${source%-*}"-$i.conf || exit 1
	sed -i "3 cAddress = $ipv4prefix$i\/24,$ipv6prefix$i\/64" "${source%-*}"-$i.conf
	echo "[Peer]
PublicKey = $public
AllowedIPs = $ipv4prefix$i/32,$ipv6prefix$i/128
$(grep PresharedKey /etc/wireguard/"$SERVER_WG_NIC".conf | head -1)
" >> /etc/wireguard/"$SERVER_WG_NIC".conf
done
echo "Starting WireGuard on interface $SERVER_WG_NIC. The new configs are ready. Your original interface config was backed up.
"
wg-quick up $SERVER_WG_NIC
