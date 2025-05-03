# RawNet

RawNet is a Go library for low-level network packet manipulation. It provides tools for parsing, inspecting, and creating raw network packets at layers 2, 3, and 4 of the OSI model.

## Features

- Parse and create Ethernet frames (Layer 2)
- Support for IPv4 and IPv6 packets (Layer 3)
- Support for TCP, UDP, ICMP, and IGMP protocols (Layer 4)
- Virtual network circuit simulation
- Checksum calculation and validation
- VLAN tagging support
- Easy packet field manipulation

## Installation

```
go get github.com/KarpelesLab/rawnet
```

## Usage

### Creating a Virtual Network Circuit

```go
// Create a new virtual network circuit
circuit := rawnet.NewCircuit()

// Bridge a device to the circuit
circuit.BridgeDevice(myNetworkDevice)

// Enable debug logging
circuit.SetDebug(true)
```

### Working with L2 Packets

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

### Working with L3 Packets

```go
// Access IP addresses
srcIP := l3p.GetSourceIP()
dstIP := l3p.GetDestinationIP()

// Create a new L3 packet with modified source
newPacket := l3p.WithNewSource(myIP, myPort)

// Create a new L3 packet with modified destination
newPacket := l3p.WithNewDst(targetIP, targetPort)
```

## Build and Test

```
make all    # Build the library
make deps   # Install dependencies
make test   # Run tests
```

## License

See the [LICENSE](LICENSE) file for details.