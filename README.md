# WireGuard installer

Easily set up a dual-stack WireGuard VPN on a Linux server. See the issues for the WIP.

## Requirements

Supported distributions:

- Ubuntu

## Usage

First, get the script and make it executable :

```sh
apt update && apt upgrade -y
apt install git
git clone https://github.com/thpryrchn/wireguard-install.git
cd wireguard-install
```

Then run it :

```sh
./wireguard-install.sh
```
