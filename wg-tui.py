#!/usr/bin/python3

"""
    wg-tui.py
    https://github.com/lavajuno/wg-tui
    Modified 2024-05-21
"""

import json
import os
import subprocess
import string
import random
import socket
from dataclasses import dataclass

DATA_DIR    = ".wg-tui/"
CONFIG_FILE = ".wg-tui/config.json"
PEERS_FILE  = ".wg-tui/peers.json"

CLIENT_HEADER = """# wg-tui client config
[Interface]
PrivateKey = {}
Address = {}/24
Address = {}/64
"""

CLIENT_DNS = "DNS = {}\n"

CLIENT_PEER = """
[Peer]
PublicKey = {}
AllowedIPs = {}
AllowedIPs = {}
Endpoint = {}
PersistentKeepalive = 1
"""

SERVER_HEADER = """# wg-tui server config
[Interface]
PrivateKey = {}
Address = {}/24
Address = {}/64
ListenPort = {}
"""

SERVER_PEER = """
[Peer]
PublicKey = {}
AllowedIPs = {}/32, {}/128
"""

SERVER_FW = """
PostUp = iptables -I FORWARD -i wg-tui -o wg-tui -j ACCEPT
PostUp = ip6tables -I FORWARD -i wg-tui -o wg-tui -j ACCEPT

PreDown = iptables -D FORWARD -i wg-tui -o wg-tui -j ACCEPT
PreDown = ip6tables -D FORWARD -i wg-tui -o wg-tui -j ACCEPT
"""

SERVER_FW_NAT = """
PostUp = iptables -t nat -I POSTROUTING -o {iface} -j MASQUERADE
PostUp = ip6tables -t nat -I POSTROUTING -o {iface} -j MASQUERADE
PostUp = iptables -I FORWARD -i wg-tui -o {iface} -j ACCEPT
PostUp = ip6tables -I FORWARD -i wg-tui -o {iface} -j ACCEPT
PostUp = iptables -I FORWARD -i {iface} -o wg-tui -j ACCEPT
PostUp = ip6tables -I FORWARD -i {iface} -o wg-tui -j ACCEPT


PreDown = iptables -t nat -D POSTROUTING -o {iface} -j MASQUERADE
PreDown = ip6tables -t nat -D POSTROUTING -o {iface} -j MASQUERADE
PreDown = iptables -D FORWARD -i wg-tui -o {iface} -j ACCEPT
PreDown = ip6tables -D FORWARD -i wg-tui -o {iface} -j ACCEPT
PreDown = iptables -D FORWARD -i {iface} -o wg-tui -j ACCEPT
PreDown = ip6tables -D FORWARD -i {iface} -o wg-tui -j ACCEPT
"""



# Utilities used by other classes
class Util:
    # Runs a command and returns its return code
    def run(args: list[str]) -> int:
        return subprocess.run(args).returncode

    # Runs a command and returns its output as a string
    def runPiped(args: list[str]) -> str:
        return subprocess.run(
                args, stdout=subprocess.PIPE
            ).stdout.decode("utf-8").strip()
    
    # Generates a wireguard private key
    def generatePrivKey() -> str:
        return subprocess.run(
            ["wg", "genkey"], stdout=subprocess.PIPE
        ).stdout.decode('utf-8').strip()

    # Generates a wireguard public key from a private key
    def generatePubKey(privkey: str) -> str:
        pk = privkey.encode('utf-8')
        return subprocess.run(
            ["wg", "pubkey"], stdout=subprocess.PIPE, input=pk
        ).stdout.decode('utf-8').strip()
    
    # Sanitizes a client name
    def sanitizeName(filename: str) -> str:
        s: str = "".join(c for c in filename if c.isalnum() or c == '-' or c == '_')
        if(s == ""):
            return "Empty"
        
        return s



# Stores global configuration
@dataclass
class Config:
    prefix4: str
    prefix6: str
    server_host: str
    server_port: int
    nat_if: str
    dns: str



# Stores a single peer's configuration
@dataclass
class Peer:
    id: int
    name: str
    priv_key: str
    pub_key: str
    addr4: str
    addr6: str



# Used to construct Peers
class PeerFactory:
    # Constructs a PeerFactory used to construct Peers with the current global configuration.
    def __init__(self, config: Config):
        self.prefix4 = config.prefix4
        self.prefix6 = config.prefix6
    
    def newPeer(self, id: int, name: str) -> Peer:
        priv_key: str = Util.generatePrivKey()
        pub_key: str = Util.generatePubKey(priv_key)
        ip4addr: str = self.prefix4 + str(id)
        ip6addr: str = self.prefix6 + str(id)
        return Peer(id, name, priv_key, pub_key, ip4addr, ip6addr)



# Provides functionality to enable and reload the Wireguard service.
class Service:
    # Enables the systemd service on the server
    def enable():
        Util.run(["sudo", "systemctl", "enable", "wg-quick@wg-tui"])
        Util.run(["sudo", "systemctl", "restart", "wg-quick@wg-tui"])
    
    # Reloads the server's wireguard config
    def reload():
        Util.run(["sudo", "systemctl", "reload", "wg-quick@wg-tui"])



# Stores and persists the current configuration, and provides functionality to
# view and edit it.
class State:
    # Constructs a State, loading the last state from the config directory
    def __init__(self):
        config_json = ""
        peers_json = ""
        with open(CONFIG_FILE, "r") as f:
            config_json = f.read()

        with open(PEERS_FILE, "r") as f:
            peers_json = f.read()

        self.__config: Config = State.deserializeConfig(config_json)
        self.__peers: dict[int, Peer] = State.deserializePeers(peers_json)
        self.__peer_factory: PeerFactory = PeerFactory(self.__config)

    # Serializes a Config to JSON
    def serializeConfig(config: Config) -> str:
        return json.dumps({
                "prefix4": config.prefix4,
                "prefix6": config.prefix6,
                "server_host": config.server_host,
                "server_port": config.server_port,
                "nat_if": config.nat_if,
                "dns": config.dns
            })
    
    # Deserializes a Config from JSON
    def deserializeConfig(config_json: str) -> Config:
        c = json.loads(config_json)
        return Config(
            c["prefix4"],
            c["prefix6"],
            c["server_host"],
            c["server_port"],
            c["nat_if"],
            c["dns"]
        )

    # Serializes peers to JSON
    def serializePeers(peers: dict[int, Peer]) -> str:
        peers_json = []
        for i in peers.values():
            peers_json.append({
                "id": i.id,
                "name": i.name,
                "priv_key": i.priv_key,
                "pub_key": i.pub_key,
                "addr4": i.addr4,
                "addr6": i.addr6
            })

        return json.dumps(peers_json)
    
    # Deserializes peers from JSON
    def deserializePeers(peers_json: str) -> dict[int, Peer]:
        peers: dict[int, Peer] = {}
        for i in json.loads(peers_json):
            peers[i["id"]] = Peer(
                i["id"],
                i["name"],
                i["priv_key"],
                i["pub_key"],
                i["addr4"],
                i["addr6"]
            )

        return peers

    # Saves state to the config directory
    def save(self):
        with open(CONFIG_FILE, "w") as f:
            f.write(State.serializeConfig(self.__config))
        with open(PEERS_FILE, "w") as f:
            f.write(State.serializePeers(self.__peers))

    # Adds a peer with the given name
    def addPeer(self, name: str) -> int|None:
        sanitized_name: str = Util.sanitizeName(name)
        for i in range(2, 254):
            if(self.__peers.get(i) == None):
                self.__peers[i] = self.__peer_factory.newPeer(i, sanitized_name)
                return i
            
        return None
    
    # Gets the peer with the given ID. Returns None if it does not exist
    def getPeer(self, id: str) -> Peer|None:
        return self.__peers.get(id)
    
    # Returns a list of all peers
    def listPeers(self) -> list[Peer]:
        res: list[Peer] = []
        for i in sorted(self.__peers.keys()):
            res.append(self.__peers[i])
            
        return res

    # Deletes the peer with the given ID
    def deletePeer(self, id: int):
        assert id > 1
        assert self.__peers.get(id) != None
        del self.__peers[id]
    
    # Renames the peer with the given ID to the new given name
    def renamePeer(self, id: int, new_name: str):
        assert self.__peers.get(id) != None
        self.__peers[id].name = Util.sanitizeName(new_name)

    # Prints a table of all peers
    def printPeers(self):
        print("+--------------------------------------------------------------------------+")
        print("| {:<3}  {:<24}  {:<15}  {:<24} |".format("ID", "NAME", "IPV4 ADDRESS", "IPV6 ADDRESS"))
        print("+  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  +")
        for i in self.listPeers():
            print("| {:<3}  {:<24}  {:<15}  {:<24} |".format(i.id, i.name, i.addr4, i.addr6))

        print("+--------------------------------------------------------------------------+")

    # Exports a single peer's configuration
    def exportPeer(self, id: int):
        assert id > 1
        assert self.__peers.get(id) != None
        peer: Peer = self.__peers[id]
        server: Peer = self.__peers[1]
        endpoint: str = "{}:{}".format(
            self.__config.server_host,
            self.__config.server_port
        )
        filename: str = "{}.conf".format(peer.name)
        s: str = CLIENT_HEADER.format(
            peer.priv_key,
            peer.addr4,
            peer.addr6
        )
        if(self.__config.dns != ""):
            s += CLIENT_DNS.format(self.__config.dns)

        if(self.__config.nat_if == ""):
            s += CLIENT_PEER.format(
                server.pub_key,
                self.__config.prefix4 + "0/24",
                self.__config.prefix6 + "/64",
                endpoint
            )

        else:
            s += CLIENT_PEER.format(
                server.pub_key,
                "0.0.0.0/0",
                "::/0",
                endpoint
            )

        if(os.path.exists(filename)):
            print("\n\"{}\" already exists. Overwrite it?".format(filename))
            if(input("(y/n) ->").lower() != "y"):
                return
            
        with open(filename, "w") as f:
            f.write(s)
            print("\nWrote \"{}\".".format(filename))

    # Exports the server's configuration and moves it to /etc/wireguard
    def configureServer(self):
        server: Peer = self.__peers[1]
        s: str = SERVER_HEADER.format(
            server.priv_key,
            server.addr4,
            server.addr6,
            self.__config.server_port
        )
        s += SERVER_FW
        if(self.__config.nat_if != ""):
            s += SERVER_FW_NAT.format(iface=self.__config.nat_if)

        for i in self.listPeers():
            if(i.id > 1):
                s += SERVER_PEER.format(
                    i.pub_key,
                    i.addr4,
                    i.addr6
                )

        with open("wg-tui-server.conf", "w") as f:
            f.write(s)

        print("\nUpdating server configuration...")
        Util.run(["sudo", "mv", "wg-tui-server.conf", "/etc/wireguard/wg-tui.conf"])
        Util.run(["sudo", "chown", "root:root", "/etc/wireguard/wg-tui.conf"])



# Functionality related to network interfaces / IP addresses
class Inet:
    # Generates a random private IPv4 prefix (192.168.xxx.0/16)
    def generateIPv4Prefix() -> str:
        return "192.168.{}.".format(random.randint(128,254))

    # Generates a random private IPv6 prefix (fdxx:xxxx:xxxx::/64)
    def generateIPv6Prefix() -> str:
        s: str = "fd"
        for i in range(2):
            s += random.choice(string.hexdigits)

        for i in range(2):
            s += ":"
            for j in range(4):
                s += random.choice(string.hexdigits)

        s += "::"
        return s.lower()
    
    # Returns a list of this machine's network interfaces
    def getInterfaces() -> list[str]:
        s: str = Util.runPiped(["ls", "-1", "/sys/class/net"])
        return s.split("\n")
    
    # Returns True if the given string is a valid IPv4 address
    def isIPv4Address(s: str) -> bool:
        try:
            socket.inet_pton(socket.AF_INET, s)

        except:
            return False
        
        return True

    # Returns True if the given string is a valid IPv6 address
    def isIPv6Address(s: str) -> bool:
        try:
            socket.inet_pton(socket.AF_INET6, s)

        except:
            return False
        
        return True
    
    # Returns True if the given string is a valid IP address
    def isIPAddress(s: str) -> bool:
        return Inet.isIPv4Address(s) or Inet.isIPv6Address(s)



# Methods for initial setup
class Setup:
    # Prompts the user to generate an IPv4 address prefix.
    def getIPv4AddressPrefix() -> str:
        print("\n\n\n=== (1/6) IPv4 Address Pool ===")
        print("Clients will be assigned IPv4 addresses from this pool.")
        print("This pool will be randomly selected from the 192.168.0.0/16 range"
                + " to minimize the chance of conflicts with other local or virtual networks.")
        while(True):
            prefix4: str = Inet.generateIPv4Prefix()
            print("\nProposed IPv4 address pool: {}0/64".format(prefix4))
            print("Use this pool?")
            if(input("(y/n) ->").lower() == "y"):
                return prefix4

    # Prompts the user to generate an IPv6 address prefix.
    def getIPv6AddressPrefix() -> str:
        print("\n\n\n=== (2/6) IPv6 Address Pool ===")
        print("Clients will be assigned IPv6 addresses from this pool.")
        print("This pool will be randomly selected from the fd00::/8 range to minimize"
                + " the chance of conflicts with other local or virtual networks.")
        while(True):
            prefix6: str = Inet.generateIPv6Prefix()
            print("\nProposed IPv6 address pool: {}/64".format(prefix6))
            print("Use this pool?")
            if(input("(y/n) ->").lower() == "y"):
                return prefix6
            
    # Prompts the user for the VPN server's hostname or IP address.
    def getServerHost() -> str:
        print("\n\n\n=== (3/6) Server Hostname / Address ===")
        print("What hostname or address should clients connect to the server with?")
        print("(ex. 'myserver.example.com', '123.123.123.123' or 'beef:cafe::')")
        while(True):
            print("\nEnter a hostname or IP address:")
            s: str = input("->")
            if(Inet.isIPAddress(s)):
                return s
            
            print("Clients will connect to \"{}\". Is this correct?".format(s))
            if(input("(y/n) ->").lower() == "y"):
                return s
    
    # Prompts the user for the VPN server's port.
    def getServerPort() -> int:
        print("\n\n\n=== (4/6) Server Port ===")
        print("What port should the server accept connections on?")
        print("A port above 1024 is recommended.")
        while(True):
            print("\nEnter a port number:")
            s: str = input("(1-65534) ->")
            try:
                i: int = int(s)
                if(i > 0 and i < 65535):
                    return i
                
            except ValueError:
                pass

    # Prompts the user to choose an interface for NAT.
    # Returns an empty string if the user does not want to set up NAT.
    def getNATInterface() -> str:
        print("\n\n\n=== (5/6) NAT ===")
        print("Configuring NAT allows connected clients to access the internet through the VPN.")
        print("If you only want to use the VPN to connect clients to each other, leave NAT unconfigured.")
        print("Would you like to configure NAT?")
        if(input("(y/n) ->").lower() != "y"):
            return "" # User does not want NAT
        
        print("\nWhich network interface should be used for NAT?")
        print("This should be the interface that this machine uses to connect to the internet.")
        interfaces: list[str] = Inet.getInterfaces()
        print("Available interfaces:")
        for i in range(0, len(interfaces)):
            print("  ({}): {}".format(i, interfaces[i]))

        while(True):
            print("\nChoose a network interface:")
            s: str = input("(0-{}) ->".format(len(interfaces) - 1))
            try:
                i: int = int(s)
                if(i < len(interfaces)):
                    return interfaces[i]
                
            except ValueError:
                pass
    
    # Prompts user to specify DNS servers for clients.
    # Returns an empty string if the user does not want to specify DNS servers.
    def getDNSServers() -> str:
        print("\n\n\n=== (6/6) DNS ===")
        print("For extra security, you can specify DNS servers for connected clients to use.")
        print("\nWould you like to specify DNS servers?")
        if(input("(y/n) ->".lower()) != "y"):
            return ""
        dns: list[str] = []
        while(True):
            while(True):
                print("\nDNS server address:")
                s: str = input("(IP address) ->")
                if(Inet.isIPAddress(s)):
                    dns.append(s)
                    break

                else:
                    print("IP address is invalid.")

            print("\nCurrent DNS servers: {}".format(", ".join(dns)))
            print("Would you like to add another DNS server?")
            if(input("(y/n) ->".lower()) != "y"):
                return ", ".join(dns)

    # Runs initial setup.
    def run():
        # Ensure presence of data directory
        os.makedirs(DATA_DIR)
        # Prompt user for setup parameters
        prefix4: str = Setup.getIPv4AddressPrefix()
        prefix6: str = Setup.getIPv6AddressPrefix()
        server_host: str = Setup.getServerHost()
        server_port: int = Setup.getServerPort()
        nat_if: str = Setup.getNATInterface()
        dns: str = Setup.getDNSServers()
        print("\n\n\nCreating initial configuration...")
        # Create initial config
        config: Config = Config(
            prefix4,
            prefix6,
            server_host,
            server_port,
            nat_if,
            dns
        )
        # Create initial peer (server)
        peers: dict[int, Peer] = {
            1: PeerFactory(config).newPeer(1, "[ Server ]")
        }
        # Write initial state to disk
        with open(CONFIG_FILE, "w") as f:
            f.write(State.serializeConfig(config))

        with open(PEERS_FILE, "w") as f:
            f.write(State.serializePeers(peers))

        # Configure and enable Wireguard service
        state: State = State()
        state.configureServer()
        Service.enable()
        Service.reload()
        print("Setup complete.")



def main():
    print("wg-tui v0.0.1-testing")
    if(not (os.path.exists(CONFIG_FILE) or os.path.exists(PEERS_FILE))):
        Setup.run()
    state: State = State()
    while(True):
        print("\nClients:")
        state.printPeers()
        print("\n- [N]ew client")
        print("- [R]ename client")
        print("- [D]elete client")
        print("- [E]xport client config")
        print("- [Q]uit")
        match(input("\n->").lower()):
            case "n":
                print("\nNew Client")
                print("New client's name: (A-Z, a-z, 0-9, dashes, and underscores)")
                i: int = state.addPeer(input("(name) ->"))
                if(i > 0):
                    state.save()
                    state.configureServer()
                    Service.reload()
                    print("Added new client with ID {}.".format(i))
                else:
                    print("Could not add client.")

            case "r":
                print("\nRename Client")
                while(True):
                    s: str = input("(ID) ->")
                    try:
                        i: int = int(s)
                        if(i == 1):
                            print("Cannot rename the server.")
                            break

                        if(state.getPeer(i) != None):
                            print("New name: (A-Z, a-z, 0-9, dashes, and underscores)")
                            state.renamePeer(i, input("(name) ->"))
                            state.save()
                            break

                    except ValueError:
                        pass

            case "d":
                print("\nDelete Client")
                while(True):
                    s: str = input("(ID) ->")
                    try:
                        i: int = int(s)
                        if(i == 1):
                            print("Cannot delete the server.")
                            break

                        if(state.getPeer(i) != None):
                            state.deletePeer(i)
                            state.save()
                            state.configureServer()
                            Service.reload()
                            break

                    except ValueError:
                        pass

            case "e":
                print("\nExport Client Config")
                while(True):
                    s: str = input("(ID) ->")
                    try:
                        i: int = int(s)
                        if(i == 1):
                            print("The server config is in /etc/wireguard.")
                            break

                        if(state.getPeer(i) != None):
                            state.exportPeer(i)
                            break

                    except ValueError:
                        pass

            case "q":
                print("Quit")
                return

if(__name__ == "__main__"):
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted")
