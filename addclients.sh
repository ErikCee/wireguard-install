#!/bin/bash
cd "$HOME" || exit
SERVER_WG_NIC="wg0"
read -rp "WireGuard interface name: " -e -i "$SERVER_WG_NIC" SERVER_WG_NIC
WG_START=3
read -rp "WireGuard Client aditional IP start: " -e -i "$WG_START" WG_START
WG_END=13
read -rp "WireGuard Client aditional IP end: " -e -i "$WG_END" WG_END
if [ -e /etc/wireguard/"$SERVER_WG_NIC".conf ]; then
	echo "Using /etc/wireguard/$SERVER_WG_NIC.conf"
else
	echo "$SERVER_WG_NIC doesn't seem to exist. Here is what is in your /etc/wireguard folder..."
	ls -1 /etc/wireguard
fi
cp /etc/wireguard/"$SERVER_WG_NIC".conf .

ipv6prefix=$(grep Address $HOME/$SERVER_WG_NIC-client.conf | awk '{ print $3 }' | sed -e 's+.*,++' ) ; ipv6prefix="${ipv6prefix%:*}:"
ipv4prefix=$(grep Address $HOME/$SERVER_WG_NIC-client.conf | awk '{ print $3 }' ) ; ipv4prefix="${ipv4prefix%.*}."
for ((i=WG_START; i<=WG_END; i++)) ; do
	private=$(wg genkey)
	public=$(echo "$private" | wg pubkey)
	sed "2 cPrivateKey = $private" "$SERVER_WG_NIC"-client.conf > "$SERVER_WG_NIC"-client-$i.conf || exit
	sed -i "3 cAddress = $ipv4prefix$i\/24,$ipv6prefix$i\/64" "$SERVER_WG_NIC"-client-$i.conf
	echo "[Peer]
PublicKey = $public
AllowedIPs = $ipv4prefix$i/32,$ipv6prefix$i/128
$(grep PresharedKey /etc/wireguard/"$SERVER_WG_NIC".conf | head -1)
" >> "$SERVER_WG_NIC".conf
done
echo "Check the $SERVER_WG_NIC.conf at $HOME/. If everything looks right, replace /etc/wireguard/$SERVER_WG_NIC.conf with it. "
