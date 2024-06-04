# wg-tui
TUI tool to configure and manage a Wireguard server.

## Features
- Create, export, and delete clients
- Easily set up NAT for remote / internet access
- Assign custom DNS servers

wg-tui handles generating and reloading Wireguard configs whenever you make a change.

## Dependencies

> Note: Make sure packet forwarding on your system is enabled! If you're unsure, uncomment `net.ipv4.ip_forward=1` and `net.ipv6.conf.all.forwarding=1` in `/etc/sysctl.conf`.

wg-tui requires Python >= 3.10, which is almost certainly included in your distro.

**Ubuntu (22.04,24.04) / Debian (11, 12):** `wireguard-tools`

```
sudo apt install -y wireguard-tools
```

**Fedora (39,40):** `wireguard-tools`
```
sudo dnf install wireguard-tools
```

**Arch Linux:** `wireguard-tools`

```
sudo pacman -S wireguard-tools
```

## Usage
To start setup, run `wg-tui.py`. You will be asked for some quick information about how you'd like your VPN to be set up.
Once setup is complete, the Wireguard service will be enabled and started.

> Note: wg-tui will not open any ports on your firewall. To ensure that clients can connect, make sure the port you choose here is open to UDP connections.

To manage clients, just run `wg-tui.py` again.

To start from scratch, remove the directory `.wg-tui`. (located in the same directory as `wg-tui.py`)

## Licensing
wg-tui is Free and Open Source Software, and is released under the BSD 2-Clause license. (See [`LICENSE`](LICENSE))
