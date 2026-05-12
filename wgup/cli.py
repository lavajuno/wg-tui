import argparse
import logging
import sys
from enum import Enum
from typing import Any

from wgup import defaults, wireguard
from wgup.config import Config
from wgup.util import (
    IP,
    ArgsException,
    ExitException,
    Input,
    InterfaceNotFoundException,
    PeerNotFoundException,
)

_logger = logging.getLogger(defaults.PROG)
_logger.setLevel(logging.INFO)
_stderr_handler = logging.StreamHandler()
_stderr_handler.setLevel(logging.DEBUG)
_stderr_handler.setFormatter(logging.Formatter("{levelname:<8} : {message}", style="{"))
_logger.addHandler(_stderr_handler)

_FMT_INTERFACES = "{iface:15} : {host}:{port}"
_FMT_PEERS = "{name:20} : {cidr4:16} : {cidr6}"
_FMT_ATTRS = "{:20} : {}"


class Iface:
    class Attributes(Enum):
        NAME = "name"
        HOST = "host"
        PORT = "port"
        NAT_IFACE = "nat_iface"

    @staticmethod
    def _get(c: Config, args: argparse.Namespace):
        """
        This function intentionally uses args instead of the name of the
        interface to ensure that positional arguments are consistent across
        subcommands.
        """
        iface = c.interfaces.get(args.interface)
        if iface is None:
            raise InterfaceNotFoundException(
                f'[!] Interface "{args.interface}" does not exist.'
            )
        return iface

    @staticmethod
    def ls(_: argparse.Namespace):
        c = Config()
        if c.interfaces:
            print("[i] Showing all interfaces.")
            for k, v in c.interfaces.items():
                print(_FMT_INTERFACES.format(iface=k, port=v.port, host=v.host))
        else:
            print("[i] No interfaces have been defined.")
        return 0

    @staticmethod
    def create(args: argparse.Namespace):
        c = Config()
        # sanitize params
        # TODO(lavajuno): write library for command line forms
        iface_name = str(args.name)
        valid, reason = Input.check_iface(iface_name)
        if not valid:
            print("[!] Interface name is invalid:")
            print(reason)
            return 1
        if c.interfaces.get(iface_name):
            print(
                "[!] An interface with this name already exists! Please choose a different name."
            )
            return 1
        cidr4 = str(args.cidr4)
        if cidr4:
            valid, reason = Input.check_cidr4(cidr4)
            if not valid:
                print("[!] IPv4 CIDR block is invalid:")
                print(reason)
                return 1
        else:
            cidr4 = IP.auto_cidr4()
        cidr6 = str(args.cidr6)
        if cidr6:
            valid, reason = Input.check_cidr6(cidr6)
            if not valid:
                print("[!] IPv4 CIDR block is invalid:")
                print(reason)
                return 1
        else:
            cidr6 = IP.auto_cidr6()
        port = int(args.port)
        valid, reason = Input.check_int(port, min_value=1, max_value=65535)
        if not valid:
            print("[!] Port is invalid:")
            print(reason)
            return 1
        host = str(args.host)
        if not host:
            print("[!] Host is required.")
            return 1
        iface = wireguard.Interface.create(
            vpn_iface=iface_name,
            vpn_cidr4=cidr4,
            vpn_cidr6=cidr6,
            host=host,
            port=port,
        )
        c.interfaces[iface_name] = iface
        c.save()
        print(f'[i] Created interface "{iface_name}".')
        return 0

    @classmethod
    def show(cls, args: argparse.Namespace):
        c = Config()
        iface = cls._get(c, args)
        print(f'[i] Showing interface "{iface.vpn_iface}".')
        print(_FMT_ATTRS.format("Public Key", iface.public_key))
        print(_FMT_ATTRS.format("VPN IPv4 Pool", iface.vpn_cidr4))
        print(_FMT_ATTRS.format("VPN IPv6 Pool", iface.vpn_cidr6))
        print(_FMT_ATTRS.format("NAT", "Enabled" if iface.nat_iface else "Disabled"))
        if iface.nat_iface:
            print(_FMT_ATTRS.format("NAT Interface", iface.nat_iface))
            print(_FMT_ATTRS.format("NAT IPv4 Dests", ", ".join(iface.nat_cidr4)))
            print(_FMT_ATTRS.format("NAT IPv6 Dests", ", ".join(iface.nat_cidr6)))
        return 0

    @classmethod
    def set(cls, args: argparse.Namespace):
        c = Config()
        iface = cls._get(c, args)
        match args.attribute:
            case cls.Attributes.NAME.value:
                raise NotImplementedError
            case cls.Attributes.HOST.value:
                iface.host = args.value
            case cls.Attributes.PORT.value:
                valid, reason = Input.check_int(
                    args.value, min_value=1, max_value=65535
                )
                if not valid:
                    print("[!] Port is invalid:")
                    print(reason)
                    return 1
                iface.port = int(args.value)
            case cls.Attributes.NAT_IFACE.value:
                valid, reason = Input.check_iface(args.value)
                if not valid:
                    print("[!] NAT interface is invalid:")
                    print(reason)
                    return 1
                iface.nat_iface = args.value
            case _:
                print(
                    f"[!] Please specify one of the following attributes: {", ".join(x.value for x in cls.Attributes)}"
                )
                return 1
        print(
            f'[i] Set {args.attribute}="{args.value}" (interface "{args.interface}").'
        )
        c.save()
        return 0

    @classmethod
    def rm(cls, args: argparse.Namespace):
        c = Config()
        _ = cls._get(c, args)  # ignore
        if not args.force:
            print("Are you sure you want to remove this interface?")
            print("This operation is irreversible!")
            print("-> (y/N):")
            if input().lower() != "y":
                print("[!] Operation cancelled by user. No action taken.")
                return 1
        del c.interfaces[args.interface]
        print(f'Removed interface "{args.interface}".')
        c.save()
        return 0

    @classmethod
    def sync(cls, args: argparse.Namespace):
        c = Config()
        iface = cls._get(c, args)
        iface_conf = iface.get_config()
        temp_filename = f"{defaults.CONFIG_DIR}/sync_temp"
        try:
            with open(temp_filename, "w") as f:
                f.write(iface_conf)
        except Exception as e:
            print(f"[!] Could not write temporary file: {str(e)}")
        iface.sync(temp_filename)
        print(f'[i] Synced interface "{args.interface}".')
        return 0

    @classmethod
    def export(cls, args: argparse.Namespace):
        c = Config()
        iface = cls._get(c, args)
        iface_conf = iface.get_config()
        if args.filename:
            try:
                with open(args.filename, "w") as f:
                    f.write(iface_conf)
                print(f'[i] Wrote "{args.filename}"')
            except Exception as e:
                print(f'[!] Could not write "{args.filename}": {str(e)}')
        else:
            print(iface_conf)
            return 1
        return 0

    @classmethod
    def up(cls, args: argparse.Namespace):
        c = Config()
        iface = cls._get(c, args)
        wireguard.CommandLine.service_up(iface.vpn_iface)
        return 0

    @classmethod
    def down(cls, args: argparse.Namespace):
        c = Config()
        iface = cls._get(c, args)
        wireguard.CommandLine.service_down(iface.vpn_iface)
        return 0

    @classmethod
    def reload(cls, args: argparse.Namespace):
        c = Config()
        iface = cls._get(c, args)
        wireguard.CommandLine.service_reload(iface.vpn_iface)
        return 0

    @classmethod
    def nat_create(cls, args: argparse.Namespace):
        if not (args.cidr4 or args.cidr6):
            raise ArgsException(
                "[!] Please specify an IPv4 or IPv6 destination (or both)."
            )
        c = Config()
        iface = cls._get(c, args)
        if args.cidr4 and args.cidr4 not in iface.nat_cidr4:
            valid, reason = Input.check_cidr4(args.cidr4)
            if not valid:
                print("[!] IPv4 CIDR is invalid:")
                print(reason)
                return 1
            iface.nat_cidr4.append(args.cidr4)
        if args.cidr6 and args.cidr6 not in iface.nat_cidr6:
            valid, reason = Input.check_cidr6(args.cidr6)
            if not valid:
                print("[!] IPv6 CIDR is invalid:")
                print(reason)
                return 1
            iface.nat_cidr6.append(args.cidr6)
        c.save()
        print(f'[i] Created NAT on interface "{args.interface}".')
        return 0

    @classmethod
    def nat_rm(cls, args: argparse.Namespace):
        if not (args.cidr4 or args.cidr6):
            raise ArgsException(
                "[!] Please specify an IPv4 or IPv6 destination (or both)."
            )
        c = Config()
        iface = cls._get(c, args)
        if args.cidr4:
            valid, reason = Input.check_cidr4(args.cidr4)
            if not valid:
                print("[!] IPv4 CIDR is invalid:")
                print(reason)
                return 1
            if args.cidr4 in iface.nat_cidr4:
                iface.nat_cidr4.remove(args.cidr4)
            else:
                raise ArgsException(
                    f'[!] NAT to {args.cidr4} does not exist on interface "{args.interface}".'
                )
        if args.cidr6:
            valid, reason = Input.check_cidr6(args.cidr6)
            if not valid:
                print("[!] IPv6 CIDR is invalid:")
                print(reason)
                return 1
            if args.cidr6 in iface.nat_cidr6:
                iface.nat_cidr6.remove(args.cidr6)
            else:
                raise ArgsException(
                    f'[!] NAT to {args.cidr6} does not exist on interface "{args.interface}".'
                )
            c.save()
        print(f'[i] Removed NAT on interface "{args.interface}".')
        return 0

    @classmethod
    def rekey(cls, args: argparse.Namespace):
        c = Config()
        iface = cls._get(c, args)
        iface.rekey()
        c.save()
        print(f'[i] Rekeyed interface "{args.interface}".')
        print(
            "    Please export its interface and peer configs again to connect using the new keys."
        )
        return 0


class Peer:
    class Attributes(Enum):
        NAME = "name"
        CIDR4 = "cidr4"
        CIDR6 = "cidr6"

    @staticmethod
    def _get(c: Config, args: argparse.Namespace):
        """
        This function intentionally uses args instead of the name of the
        interface+peer to ensure that positional arguments are consistent
        across subcommands.
        """
        iface = c.interfaces.get(args.interface)
        if iface is None:
            raise InterfaceNotFoundException(
                f'[!] Interface "{args.interface}" does not exist.'
            )
        peer = iface.peers.get(args.peer)
        if peer is None:
            raise PeerNotFoundException(f'[!] Peer "{args.peer}" does not exist.')
        return iface, peer

    @staticmethod
    def __next_addr4(interface: wireguard.Interface):
        peer_cidr4 = list(peer.cidr4 for peer in interface.peers.values())
        return IP.next_addr4(interface.vpn_cidr4, peer_cidr4)

    @staticmethod
    def __next_addr6(interface: wireguard.Interface):
        peer_cidr6 = list(peer.cidr6 for peer in interface.peers.values())
        return IP.next_addr6(interface.vpn_cidr6, peer_cidr6)

    @classmethod
    def create(cls, args: argparse.Namespace):
        c = Config()
        if not c.interfaces.get(args.interface):
            print(f'No such interface: "{args.interface}".')
            return 1
        interface = c.interfaces[args.interface]
        # sanitize params
        # TODO(lavajuno): write library for command line forms
        peer_name = str(args.name)
        valid, reason = Input.check_peer_name(peer_name)
        if not valid:
            print("[!] Peer name is invalid:")
            print(reason)
            return 1
        if interface.peers.get(peer_name):
            print(
                "[!] A peer with this name already exists! Please choose a different name."
            )
            return 1
        cidr4 = str(args.cidr4)
        if cidr4:
            valid, reason = Input.check_cidr4(cidr4)
            if not valid:
                print("[!] IPv4 CIDR block is invalid:")
                print(reason)
                return 1
        else:
            cidr4 = cls.__next_addr4(interface)
        cidr6 = str(args.cidr6)
        if cidr6:
            valid, reason = Input.check_cidr6(cidr6)
            if not valid:
                print("[!] IPv6 CIDR block is invalid:")
                print(reason)
                return 1
        else:
            cidr6 = cls.__next_addr6(interface)
        peer = wireguard.Peer.create(name=peer_name, cidr4=cidr4, cidr6=cidr6)
        interface.peers[peer_name] = peer
        c.save()
        print(f'[i] Created peer "{peer_name}" for interface "{args.interface}".')
        return 0

    @classmethod
    def ls(cls, args: argparse.Namespace):
        c = Config()
        iface = c.interfaces.get(args.interface)
        if iface is None:
            print(f'[!] Interface "{args.interface}" does not exist.')
            return 1
        if iface.peers:
            print(f'[i] Showing peers for "{iface.vpn_iface}".')
            for k, v in iface.peers.items():
                print(_FMT_PEERS.format(name=k, cidr4=v.cidr4, cidr6=v.cidr6))
        else:
            print("[i] No peers have been defined for this interface.")
        return 0

    @classmethod
    def show(cls, args: argparse.Namespace):
        c = Config()
        iface = c.interfaces.get(args.interface)
        if iface is None:
            print(f'[!] Interface "{args.interface}" does not exist.')
            return 1
        peer = iface.peers.get(args.peer)
        if peer is None:
            print(f'[!] Peer "{args.peer}" does not exist.')
            return 1
        print(f'[i] Showing peer "{args.peer}" (on interface {args.interface}).')
        print(_FMT_ATTRS.format("Public Key", peer.public_key))
        print(_FMT_ATTRS.format("IPv4 CIDR", peer.cidr4))
        print(_FMT_ATTRS.format("IPv6 CIDR", peer.cidr6))
        return 0

    @classmethod
    def export(cls, args: argparse.Namespace):
        c = Config()
        iface = c.interfaces.get(args.interface)
        if iface is None:
            print(f'[!] Interface "{args.interface}" does not exist.')
            return 1
        peer = iface.peers.get(args.peer)
        if peer is None:
            print(f'[!] Peer "{args.peer}" does not exist.')
            return 1
        peer_conf = peer.get_config(
            vpn_cidr4=iface.vpn_cidr4,
            vpn_cidr6=iface.vpn_cidr6,
            nat_cidr4=iface.nat_cidr4,
            nat_cidr6=iface.nat_cidr6,
            endpoint_public_key=iface.public_key,
            endpoint_host=iface.host,
            endpoint_port=iface.port,
        )
        if args.filename:
            try:
                with open(args.filename, "w") as f:
                    f.write(peer_conf)
                print(f'[i] Wrote "{args.filename}"')
            except Exception as e:
                print(f'[i] Could not write "{args.filename}": {str(e)}')
        else:
            print(peer_conf)
            return 1
        return 0

    @classmethod
    def set(cls, args: argparse.Namespace):
        c = Config()
        _, peer = cls._get(c, args)
        match args.attribute:
            case cls.Attributes.NAME.value:
                raise NotImplementedError
            case cls.Attributes.CIDR4.value:
                # TODO ensure CIDRs are in network and unused
                valid, reason = Input.check_cidr4(args.value)
                if not valid:
                    print("[!] IPv4 CIDR block is invalid:")
                    print(reason)
                    return 1
                peer.cidr4 = args.value
            case cls.Attributes.CIDR6.value:
                valid, reason = Input.check_cidr6(args.value)
                if not valid:
                    print("[!] IPv6 CIDR block is invalid:")
                    print(reason)
                    return 1
                peer.cidr6 = args.value
            case _:
                print(
                    f"[!] Please specify one of the following attributes: {", ".join(x.value for x in cls.Attributes)}"
                )
                return 1
        print(
            f'[i] Set {args.attribute}="{args.value}" (peer "{args.peer}" on {args.interface}).'
        )
        c.save()
        return 0

    @classmethod
    def rm(cls, args: argparse.Namespace):
        c = Config()
        iface, _ = cls._get(c, args)
        if not args.force:
            print("Are you sure you want to remove this peer?")
            print("This operation is irreversible!")
            print("-> (y/N):")
            if input().lower() != "y":
                print("[!] Operation cancelled by user. No action taken.")
                return 1
        del iface.peers[args.peer]
        print(f'Removed peer "{args.peer}" (on {args.interface}).')
        c.save()
        return 0

    @classmethod
    def rekey(cls, args: argparse.Namespace):
        c = Config()
        _, peer = cls._get(c, args)
        peer.rekey()
        c.save()
        print(f'[i] Rekeyed peer "{args.peer}" (on {args.interface}).')
        print(
            "    Please export the peer's config again to connect using the new keys."
        )
        return 0


class Version:
    @staticmethod
    def display(_: argparse.Namespace):
        print(
            f"{defaults.PROG} v{defaults.VERSION} (config version {defaults.CONFIG_VERSION})"
        )
        return 0


@staticmethod
def get_parser():
    # root
    root = argparse.ArgumentParser(defaults.PROG)
    root_sub = root.add_subparsers(title="subcommands", required=True)

    # iface.*
    iface = root_sub.add_parser("iface", help="Manage interfaces")
    iface_sub = iface.add_subparsers(title="subcommands", required=True)

    # iface.ls
    interface_ls = iface_sub.add_parser("ls", help="List all interfaces")
    interface_ls.set_defaults(func=Iface.ls)

    # iface.create
    iface_create = iface_sub.add_parser("create", help="Create an interface")
    iface_create.set_defaults(func=Iface.create)
    iface_create.add_argument("name", type=str, default="")
    iface_create.add_argument("--cidr4", type=str, default="")
    iface_create.add_argument("--cidr6", type=str, default="")
    iface_create.add_argument("--nat_iface", type=str, default="")
    iface_create.add_argument("--host", type=str, required=True)
    iface_create.add_argument("--port", type=int, required=True)

    # iface.show
    iface_show = iface_sub.add_parser("show", help="Show details for an interface")
    iface_show.set_defaults(func=Iface.show)
    iface_show.add_argument("interface", type=str)

    # iface.set
    iface_set = iface_sub.add_parser("set", help="Set parameters for an interface")
    iface_set.set_defaults(func=Iface.set)
    iface_set.add_argument("interface", type=str)
    iface_set.add_argument("attribute", type=str)
    iface_set.add_argument("value", type=str)

    # iface.remove
    iface_rm = iface_sub.add_parser("rm", help="Remove an interface")
    iface_rm.set_defaults(func=Iface.rm)
    iface_rm.add_argument("interface", type=str)
    iface_rm.add_argument("--force", action="store_true")

    # iface.export
    iface_export = iface_sub.add_parser(
        "export", help="Export config file for an interface"
    )
    iface_export.set_defaults(func=Iface.export)
    iface_export.add_argument("interface", type=str)
    iface_export.add_argument("-f", "--filename", type=str)

    # iface.up
    iface_up = iface_sub.add_parser(
        "up", help="Bring an interface up and enable its systemd target"
    )
    iface_up.set_defaults(func=Iface.up)
    iface_up.add_argument("interface", type=str)

    # iface.down
    iface_down = iface_sub.add_parser(
        "down", help="Bring an interface down and disable its systemd target"
    )
    iface_down.set_defaults(func=Iface.down)
    iface_down.add_argument("interface", type=str)

    # iface.reload
    iface_reload = iface_sub.add_parser(
        "reload", help="Tell systemd to reload an interface's config"
    )
    iface_reload.set_defaults(func=Iface.reload)
    iface_reload.add_argument("interface", type=str)

    # iface.rekey
    iface_rekey = iface_sub.add_parser(
        "rekey", help="Generate new keys for an interface and its peers"
    )
    iface_rekey.set_defaults(func=Iface.rekey)
    iface_rekey.add_argument("interface", type=str)

    # iface.sync
    iface_sync = iface_sub.add_parser(
        "sync", help="Update an interface's config in /etc/wireguard"
    )
    iface_sync.set_defaults(func=Iface.sync)
    iface_sync.add_argument("interface", type=str)

    # peer.*
    peer = root_sub.add_parser("peer", help="Manage peers")
    peer_sub = peer.add_subparsers()

    # peer.ls
    peer_ls = peer_sub.add_parser("ls", help="Show peers defined for an interface")
    peer_ls.set_defaults(func=Peer.ls)
    peer_ls.add_argument("interface", type=str)

    # peer.create
    peer_create = peer_sub.add_parser(
        "create", help="Create a new peer for the given interface"
    )
    peer_create.set_defaults(func=Peer.create)
    peer_create.add_argument("interface", type=str)
    peer_create.add_argument("name", type=str, default="")
    peer_create.add_argument("--cidr4", type=str, default="")
    peer_create.add_argument("--cidr6", type=str, default="")

    # peer.show
    peer_show = peer_sub.add_parser("show", help="Show details for a peer")
    peer_show.set_defaults(func=Peer.show)
    peer_show.add_argument("interface", type=str)
    peer_show.add_argument("peer", type=str)

    # peer.export
    peer_export = peer_sub.add_parser("export", help="Export config file for a peer")
    peer_export.set_defaults(func=Peer.export)
    peer_export.add_argument("interface", type=str)
    peer_export.add_argument("peer", type=str)
    peer_export.add_argument("-f", "--filename", type=str)

    # peer.set
    peer_set = peer_sub.add_parser("set")
    peer_set.set_defaults(func=Peer.set)
    peer_set.add_argument("interface", type=str)
    peer_set.add_argument("peer", type=str)
    peer_set.add_argument("attribute", type=str)
    peer_set.add_argument("value", type=str)

    # peer.rm
    peer_rm = peer_sub.add_parser("rm")
    peer_rm.set_defaults(func=Peer.rm)
    peer_rm.add_argument("interface", type=str)
    peer_rm.add_argument("peer", type=str)
    peer_rm.add_argument("--force", action="store_true")

    # peer.rekey
    peer_rekey = peer_sub.add_parser("rekey")
    peer_rekey.set_defaults(func=Peer.rekey)
    peer_rekey.add_argument("interface", type=str)
    peer_rekey.add_argument("peer", type=str)

    # nat.*
    nat = root_sub.add_parser("nat", help="Manage NATs")
    nat_sub = nat.add_subparsers(title="subcommands", required=True)

    # nat.create
    nat_create = nat_sub.add_parser("create", help="Create a NAT")
    nat_create.set_defaults(func=Iface.nat_create)
    nat_create.add_argument("interface", type=str)
    nat_create.add_argument("--cidr4", type=str, default="")
    nat_create.add_argument("--cidr6", type=str, default="")

    # nat.rm
    nat_rm = nat_sub.add_parser("rm", help="Remove a NAT")
    nat_rm.set_defaults(func=Iface.nat_rm)
    nat_rm.add_argument("interface", type=str)
    nat_rm.add_argument("--cidr4", type=str, default="")
    nat_rm.add_argument("--cidr6", type=str, default="")

    # version
    version = root_sub.add_parser("version", help="Show version information")
    version.set_defaults(func=Version.display)

    return root  # parser


def entrypoint():
    parser = get_parser()
    args = parser.parse_args(sys.argv[1:])
    try:
        status = int(args.func(args))
        return status
    except ExitException as e:
        print(str(e))
        return 1
