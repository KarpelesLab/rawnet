[![Go Reference](https://pkg.go.dev/badge/github.com/KarpelesLab/rawnet.svg)](https://pkg.go.dev/github.com/KarpelesLab/rawnet)

# RawNet

> **⚠️ DEPRECATED — use [github.com/KarpelesLab/pktkit](https://github.com/KarpelesLab/pktkit) instead.**
>
> This package is no longer maintained. All development has moved to
> [`pktkit`](https://github.com/KarpelesLab/pktkit), which is a rewrite with
> a zero-copy data plane, far broader feature coverage (DHCP, NAT, WireGuard,
> OpenVPN, TUN/TAP, QEMU, slirp userspace stack), and a comprehensive test
> suite. New code should depend on `pktkit`; existing users are encouraged
> to migrate.

RawNet is a Go library for low-level network packet manipulation. It provides tools for parsing, inspecting, and creating raw network packets at layers 2, 3, and 4 of the OSI model.

## Why migrate?

`pktkit` is the successor to `rawnet` and improves on it in every dimension:

- **Zero-copy hot path** — `Frame` and `Packet` are `[]byte` type aliases with
  typed header accessors, so there are no wrapper allocations per packet. The
  old `rawnet` API allocated an interface-typed `Frame` per layer per packet.
- **Callback-based forwarding** — devices expose a `Send(frame) error` /
  `SetHandler(func)` pair instead of the heavier `HandleL2Packet(src, pkt)`
  pattern. Wiring two devices together is one call (`ConnectL2`/`ConnectL3`).
- **MAC-learning L2 hub** — `L2Hub` learns source MACs and forwards unicast
  only to the correct port (with 5-minute aging), instead of broadcasting
  every frame like `rawnet.VirtualCircuit` did.
- **Built-in IP routing** — `L3Hub` does prefix-based routing for IPv4 and
  IPv6, with proper broadcast and multicast handling.
- **Built-in protocols** — DHCP client and server, ARP, NDP, ICMPv6, IPv4 NAT
  with ALGs (FTP, SIP, H.323, PPTP, TFTP, IRC), NAT64, and defragmentation.
- **VPN and tunnel devices** — WireGuard (`wg`), OpenVPN (`ovpn`), QEMU
  socket protocol (`qemu`), TUN/TAP (`tuntap`), and a userspace NAT stack
  (`slirp`).
- **Virtual client** — `vclient` provides `Dial`, `Listen`, `net.Conn`, DNS,
  and `http.Client` over a virtual L3 network.
- **Comprehensive tests and benchmarks** — see the `pktkit` README for the
  throughput numbers.

## Migration guide

The two libraries do not share an import path or any types, so migration is
not automatic. The mapping below covers the most common API surface.

### Imports

```go
// old
import "github.com/KarpelesLab/rawnet"

// new
import "github.com/KarpelesLab/pktkit"
```

### Packets and frames

| rawnet                       | pktkit                                                 |
|------------------------------|--------------------------------------------------------|
| `L2Packet` (interface)       | `Frame` (`[]byte` alias with typed accessors)          |
| `L3Packet` (interface)       | `Packet` (`[]byte` alias with typed accessors)         |
| `pkt.GetSourceMac()`         | `frame.SrcMAC()`                                       |
| `pkt.GetDestinationMac()`    | `frame.DstMAC()`                                       |
| `pkt.GetEthertype()`         | `frame.EtherType()`                                    |
| `pkt.GetVLan()`              | `frame.VLAN()`                                         |
| `pkt.GetL3Packet()`          | `frame.Payload()` + `frame.EtherType()`                |
| `l3p.GetSourceIP()`          | `packet.SrcAddr()` (returns `netip.Addr`)              |
| `l3p.GetDestinationIP()`     | `packet.DstAddr()` (returns `netip.Addr`)              |
| `l3p.WithNewSource(ip, port)`| set in place: `packet.SetIPv4SrcAddr(addr)` + port via the L4 accessor, then recompute checksums with `checksum` helpers |

### Devices

| rawnet                                          | pktkit                                                 |
|-------------------------------------------------|--------------------------------------------------------|
| `L2Device.HandleL2Packet(src, pkt) error`       | `L2Device.Send(Frame) error` + `SetHandler(func(Frame) error)` |
| `L3Device.HandleL3Packet(proto, pkt) error`     | `L3Device.Send(Packet) error` + `SetHandler(func(Packet) error)` |
| `BaseL3` / `NewBaseL3`                          | implement `L3Device` directly, or use `L2Adapter` to bridge an L3 device onto L2 |

### Topology

| rawnet                                | pktkit                                                   |
|---------------------------------------|----------------------------------------------------------|
| `c := rawnet.NewCircuit()`            | `hub := pktkit.NewL2Hub()` (MAC-learning, not flood-only) |
| `c.BridgeDevice(dev)`                 | `hub.Connect(dev)`                                       |
| `c.SetDebug(true)`                    | use a logger on the hub's options (see godoc)            |
| ad-hoc point-to-point wiring          | `pktkit.ConnectL2(a, b)` or `pktkit.ConnectL3(a, b)`     |
| (no equivalent)                       | `pktkit.NewL3Hub()` for IP-level routing                 |
| (no equivalent)                       | `pktkit.Serve(listener, connector)` for accept loops     |

### Side-by-side example

Old `rawnet` style:

```go
circuit := rawnet.NewCircuit()
circuit.BridgeDevice(dev1)
circuit.BridgeDevice(dev2)
```

New `pktkit` style:

```go
hub := pktkit.NewL2Hub()
hub.Connect(dev1)
hub.Connect(dev2)
```

For a virtual LAN with DHCP and NAT, or for VPN / QEMU / TUN setups, see the
[pktkit README](https://github.com/KarpelesLab/pktkit/blob/master/README.md)
— these have no equivalent in `rawnet`.

## Original documentation (for existing users)

### Features

- Parse and create Ethernet frames (Layer 2)
- Support for IPv4 and IPv6 packets (Layer 3)
- Support for TCP, UDP, ICMP, and IGMP protocols (Layer 4)
- Virtual network circuit simulation
- Checksum calculation and validation
- VLAN tagging support
- Easy packet field manipulation

### Installation

```
go get github.com/KarpelesLab/rawnet
```

### Usage

#### Creating a Virtual Network Circuit

```go
// Create a new virtual network circuit
circuit := rawnet.NewCircuit()

// Bridge a device to the circuit
circuit.BridgeDevice(myNetworkDevice)

// Enable debug logging
circuit.SetDebug(true)
```

#### Working with L2 Packets

```go
// Handle an L2 packet
func (d *MyDevice) HandleL2Packet(src rawnet.L2Device, pkt rawnet.L2Packet) error {
    // Get source and destination MAC addresses
    srcMac := pkt.GetSourceMac()
    dstMac := pkt.GetDestinationMac()
    
    // Get ethertype and VLAN info
    ethertype, vlan, l3p := pkt.GetL3Packet()
    
    // Process based on packet type
    // ...
}
```

#### Working with L3 Packets

```go
// Access IP addresses
srcIP := l3p.GetSourceIP()
dstIP := l3p.GetDestinationIP()

// Create a new L3 packet with modified source
newPacket := l3p.WithNewSource(myIP, myPort)

// Create a new L3 packet with modified destination
newPacket := l3p.WithNewDst(targetIP, targetPort)
```

### Build and Test

```
make all    # Build the library
make deps   # Install dependencies
make test   # Run tests
```

## License

See the [LICENSE](LICENSE) file for details.
