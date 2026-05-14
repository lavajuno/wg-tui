# wgup

![Downloads badge](https://img.shields.io/pypi/dm/wgup)
![Package status badge](https://img.shields.io/github/actions/workflow/status/lavajuno/wgup/build-wheel.yml?label=package)
![Tests status badge](https://img.shields.io/github/actions/workflow/status/lavajuno/wgup/unit-tests.yml?label=tests)
![Python version badge](https://img.shields.io/python/required-version-toml?tomlFilePath=https%3A%2F%2Fraw.githubusercontent.com%2Flavajuno%2Fwgup%2Frefs%2Fheads%2Fmain%2Fpyproject.toml&logo=python)
![License badge](https://img.shields.io/github/license/lavajuno/wgup)

Scriptable shortcuts for managing WireGuard interfaces.
Works with (and alongside) [wg-quick](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8).

wgup lets you __create common setups in seconds__, while leaving room for advanced configurations.

![Demo](doc/img/demo.gif)

> NOTE: This project is an early work in progress. Features and
> documentation WILL be missing.

## Installation

Install as a Python package:

```
pip install wgup
```

Or, install as a standalone utility:

```
pipx install wgup
```

## Features
- wgup handles generation and management of keys
- wgup handles IP address pool selection and assignment
    - Of course, you can still assign pools and IPs manually. wgup's automatic
    assignments will work around existing manual assignments.
- wgup generates firewall rules and NATs
- wgup supplements core WireGuard tools -- it does not replace them.

## Dependencies

> Note: Make sure packet forwarding on your system is enabled! If you're unsure,
uncomment `net.ipv4.ip_forward=1` and `net.ipv6.conf.all.forwarding=1` in
`/etc/sysctl.conf`.

wgup requires Python >= 3.10, which is almost certainly included in your
distro.

**Ubuntu (22.04, 24.04, 26.04) / Debian (12, 13):** `wireguard-tools`

```
sudo apt install wireguard-tools
```

**Fedora (39+):** `wireguard-tools`
```
sudo dnf install wireguard-tools
```

**Arch Linux:** `wireguard-tools`

```
sudo pacman -S wireguard-tools
```

## Notes

- wgup will never open a port on your firewall. To ensure that clients can
connect, make sure your interfaces' ports are open to incoming UDP traffic.

- wgup is opinionated. Certain things like the keepalive interval and the host
machine's VPN address are defined by wgup. In the future I hope to provide
defaults that work for most setups, while allowing customization.

- wgup is agentless. If you reconfigure an interface or a peer, you will need to
export and apply the configs before they will work.

- wgup **stores peer keys on the host**. My reasoning is that these keys should
only be used to identify the peer to the host. Keys should be unique to each
interface<->peer connection, so if the host machine is compromised, its peers
connections to other machines are not at risk.

- wgup stores its configuration in `~/.wgup`.

- wgup allows you to perform elevated operations (copying files to
/etc/wireguard and managing systemd targets for interfaces). Please take a look
at the code for `wgup.wireguard.CommandLine` to see what it's doing.

## Usage

### Help

Help (hopefully helpful) exists for wgup and all its subcommands, and may be a
better TLDR than this README.

Use the `-h` or `--help` flag with any command for help.

```bash
wgup --help
wgup iface --help
wgup peer --help
wgup nat --help
```

### Managing interfaces

The following creates a new interface called "wg0". Peers will be configured to
connect to "vpn.example.com:51820".

```bash
wgup iface create wg0 --host vpn.example.com --port 51820
```

You may also specify IP address pools for the interface to use. If you leave
them out, wgup will choose random private pools to reduce the chance of a
conflict.

```bash
wgup iface create wg0 --cidr4 172.31.0.0/24 --cidr6 2001:db8::/64 --host vpn.example.com --port 51820
```

> The machine hosting the interface will always be assigned the first IP address
> in the pool, both for IPv4 and IPv6.

To see the interface you just created:

```bash
wgup iface show wg0
```

To see all interfaces managed by wgup:

```bash
wgup iface ls
```

To modify an interface's parameters after creating it:

```bash
wgup iface set wg0 cidr4 172.31.1.0/24
wgup iface set wg0 cidr6 2001:db8::1/64
wgup iface set wg0 name wg1
```

To rekey an interface (generates new keys for the interface and all its peers):

```bash
wgup iface rekey wg0
```


To export an interface's config for use:

```bash
wgup iface sync wg0  # syncs config to /etc/wireguard (recommended)
wgup iface export wg0 # prints config to stdout
wgup iface export wg0 --filename=wg0.conf # exports config to a file
```

### Managing peers

To create a new peer called "laptop":

```bash
wgup peer create wg0 laptop
```

As is the case with interfaces, you can also specify an IP address pool for the
peer to use. Usually these are single addresses (/32 for IPv4, /128 for IPv6),
but it is often desirable to route a pool of addresses to a peer in more
advanced setups.

If you do not specify IP addresses, wgup will choose the next available ones.

```bash
wgup peer create wg0 laptop --cidr4 172.31.0.123/32 --cidr6 2001:db8::beef/32
```

To see the peer you just created:
```bash
wgup peer show wg0 laptop
```

To see all peers on "wg0":
```bash
wgup iface ls
```

To modify a peer's parameters after creating it:
```bash
wgup peer set wg0 laptop cidr4 172.31.0.5/32
wgup peer set wg0 laptop cidr6 2001:db8::cafe/32
wgup peer set wg0 laptop name cooler_laptop
```

To rekey a peer (generates new keys for this peer only):
```bash
wgup peer rekey wg0 laptop
```

To export a peer's config for use:

```bash
wgup peer export wg0 laptop  # prints to stdout by default
wgup peer export wg0 laptop --filename laptop_wg.conf
```

### Managing NATs

> NOTE: After making changes to NATs, you need to export peer configs again for
> the new or removed routes to take effect.

To specify a physical interface to NAT traffic to:

```bash
wgup iface set wg0 nat_iface eth0
```

To NAT all traffic from "wg0":

```bash
wgup nat create wg0 --cidr4 0.0.0.0/0 --cidr6 ::/0
```

> You must include either an IPv4 or IPv6 destination (or both).

To remove an existing NAT:

```bash
wgup nat rm wg0 --cidr4 0.0.0.0/0
```

## Licensing
wgup is Free and Open Source Software, and is released under the BSD 2-Clause license. (See [`LICENSE`](LICENSE))
