# wg-tui
TUI tool to configure and manage a Wireguard server.

## Features
- Create, export, and delete clients
- Easily set up NAT for remote / internet access
- Assign custom DNS servers

wg-tui handles generating and reloading Wireguard configs whenever you make a change.

## Dependencies

wg-tui requires Python >= 3.10.

**Ubuntu (22.04,24.04) / Debian (11, 12):** `wireguard`, `wireguard-tools`

```
sudo apt install -y wireguard wireguard-tools
```

**Arch Linux:** `wireguard-tools`

```
sudo pacman -S wireguard-tools
```

## Usage
To start setup, run `wg-tui.py`. You will be asked for some quick information about how you'd like your VPN to be set up.
Once setup is complete, the Wireguard service will be enabled and started.

To manage clients, just run `wg-tui.py` again.

To start from scratch, remove the directory `.wg-tui`. (located in the same directory as `wg-tui.py`)

## Licensing
wg-tui is Free and Open Source Software, and is released under the BSD 2-Clause license. (See [`LICENSE`](LICENSE))
