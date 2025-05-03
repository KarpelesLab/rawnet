package rawnet

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Package rawnet provides utilities for working with network packets at various layers.
// These utilities make certain assumptions to optimize performance while providing
// a simple API for packet manipulation.

// Layer2 means packet starts with ethernet header (14 bytes, 18 if 802.1Q tag)
// Layer3 means packet starts at IP level

// L2Packet represents a Layer 2 network packet (Ethernet frame).
// It's a byte slice that starts with an Ethernet header and provides methods
// for easily accessing and manipulating Ethernet header fields.
type L2Packet []byte

// L3Packet represents a Layer 3 network packet (IP packet).
// It's a byte slice that starts with an IP header and provides methods
// for easily accessing and manipulating IP header fields.
type L3Packet []byte

// Packet is an interface for any network packet type.
// It provides a method to determine the OSI layer at which this packet operates.
type Packet interface {
	// GetPacketLayer returns the OSI model layer number that this packet operates at.
	// For example, Ethernet is layer 2, IP is layer 3, TCP is layer 4.
	GetPacketLayer() int
}

// GetPacketLayer implements the Packet interface for L2Packet.
// Always returns 2 as Ethernet operates at OSI layer 2 (data link layer).
func (p L2Packet) GetPacketLayer() int {
	return 2
}

// GetDestinationMac returns the destination MAC address from the Ethernet header.
// This is the first 6 bytes of the frame.
func (p L2Packet) GetDestinationMac() net.HardwareAddr {
	return net.HardwareAddr(p[0:6])
}

// GetSourceMac returns the source MAC address from the Ethernet header.
// This is bytes 6-12 of the frame.
func (p L2Packet) GetSourceMac() net.HardwareAddr {
	return net.HardwareAddr(p[6:12])
}

// GetEthertype returns the EtherType value from the Ethernet header.
// This indicates the protocol of the encapsulated data.
func (p L2Packet) GetEthertype() Protocol {
	res := Protocol(uint16(p[12])<<8 | uint16(p[13]))
	//if res == ProtoVLAN {
	// 802.1Q header (vlan tagging)
	//	res = Protocol(uint16(p[16])<<8 | uint16(p[17]))
	//}
	return res
}

// GetVLan extracts the VLAN ID from the frame if it has 802.1Q tagging.
// Returns 0 if there is no VLAN tag.
func (p L2Packet) GetVLan() uint16 {
	ethertype := Protocol(uint16(p[12])<<8 | uint16(p[13]))
	if ethertype != ProtoVLAN {
		return 0 // no vlan tagging
	}
	return uint16(p[14])<<8 | uint16(p[15])
}

// GetL3Packet extracts the Layer 3 packet from this Ethernet frame.
// It returns the EtherType, VLAN ID (if present), and the Layer 3 packet data.
// For VLAN-tagged frames, it properly skips the 802.1Q header.
func (p L2Packet) GetL3Packet() (Protocol, uint16, L3Packet) {
	ethertype := Protocol(uint16(p[12])<<8 | uint16(p[13]))
	if ethertype == ProtoVLAN {
		vlan := uint16(p[14])<<8 | uint16(p[15])
		ethertype = Protocol(uint16(p[16])<<8 | uint16(p[17]))
		return ethertype, vlan, L3Packet(p[18:])
	}

	return ethertype, 0, L3Packet(p[14:])
}

// GetPacketLayer implements the Packet interface for L3Packet.
// Always returns 3 as IP operates at OSI layer 3 (network layer).
func (p L3Packet) GetPacketLayer() int {
	return 3
}

// GetSrcDst extracts both source and destination addresses (IP and ports) into provided buffers.
// For IPv4, src/dst buffers should be at least 6 bytes (4 for IP, 2 for port).
// For IPv6, src/dst buffers should be at least 18 bytes (16 for IP, 2 for port).
// Returns the protocol type (TCP, UDP, etc.) if available.
func (p L3Packet) GetSrcDst(src, dst []byte) Protocol {
	// get source & destination of packet. src/dst len must be 6 bytes in ipv4, 18 bytes in ipv6
	switch (p[0] >> 4) & 0xf {
	case 4: // ipv4 → p[12:20] (src, dst)
		copy(src[:4], p[12:16])
		copy(dst[:4], p[16:20])
		switch p[9] {
		case 0x01: // icmp → read icmp packet type so we know what the deal is.
			return 0 // TODO
		case 0x06, 0x11: // tcp, udp
			ip_header_size := int(p[0]&0xf) << 2
			// src, dst at ip_header_size:ip_header_size+4
			copy(src[4:6], p[ip_header_size:ip_header_size+2])
			copy(dst[4:6], p[ip_header_size+2:ip_header_size+4])
			return Protocol(p[9])
		}
	case 6: // ipv6 → p[8:40] (src, dst)
		copy(src[:16], p[8:24])
		copy(dst[:16], p[24:40])
		switch p[6] {
		case 58: // icmp6 → read icmp packet type so we know what the deal is.
			return 0 // TODO
		case 0x06, 0x11:
			copy(src[16:18], p[40:42])
			copy(dst[16:18], p[42:44])
			return Protocol(p[6])
		}
	}
	return 0
}

// WithNewSource creates a copy of the packet with a new source IP address and port.
// It properly handles both IPv4 and IPv6 packets and recalculates checksums.
// Returns nil if the operation is not supported for the given protocol or IP version.
func (p L3Packet) WithNewSource(src net.IP, port uint16) L3Packet {
	// duplicate packet
	p2 := make([]byte, len(p))
	copy(p2, p)

	// overwrite source
	switch (p[0] >> 4) & 0xf {
	case 4: // ipv4 → p[12:16](src)
		if len(src) != 4 {
			src = src.To4()
			if src == nil {
				// not ipv4??
				return nil
			}
		}
		copy(p2[12:16], src)
		switch p[9] {
		case 0x01: // icmp → read icmp packet type so we know what the deal is.
			return nil // TODO
		case 0x06, 0x11: // tcp, udp
			ip_header_size := int(p[0]&0xf) << 2
			// src at ip_header_size:ip_header_size+2
			binary.BigEndian.PutUint16(p2[ip_header_size:ip_header_size+2], port)
			L3Packet(p2).ComputeChecksums()
			return L3Packet(p2)
		}
	case 6: // ipv6 → p[8:24](src)
		copy(p2[8:24], src)
		switch p[6] {
		case 58: // icmp6 → read icmp packet type so we know what the deal is.
			return nil // TODO
		case 0x06, 0x11: // tcp, udp
			binary.BigEndian.PutUint16(p2[40:42], port)
			L3Packet(p2).ComputeChecksums()
			return L3Packet(p2)
		}
	}
	return nil
}

// WithNewDst creates a copy of the packet with a new destination IP address and port.
// It properly handles both IPv4 and IPv6 packets and recalculates checksums.
// Returns nil if the operation is not supported for the given protocol or IP version.
func (p L3Packet) WithNewDst(dst net.IP, port uint16) L3Packet {
	// duplicate packet
	p2 := make([]byte, len(p))
	copy(p2, p)

	// overwrite destination
	switch (p[0] >> 4) & 0xf {
	case 4: // ipv4 → p[16:20](dst)
		if len(dst) != 4 {
			dst = dst.To4()
			if dst == nil {
				// not ipv4??
				return nil
			}
		}
		copy(p2[16:20], dst)
		switch p[9] {
		case 0x01: // icmp → read icmp packet type so we know what the deal is.
			return nil // TODO
		case 0x06, 0x11: // tcp, udp
			ip_header_size := int(p[0]&0xf) << 2
			// dst at ip_header_size+2:ip_header_size+4
			binary.BigEndian.PutUint16(p2[ip_header_size+2:ip_header_size+4], port)
			L3Packet(p2).ComputeChecksums()
			return L3Packet(p2)
		}
	case 6: // ipv6 → p[24:40](dst)
		copy(p2[24:40], dst)
		switch p[6] {
		case 58: // icmp6 → read icmp packet type so we know what the deal is.
			return nil // TODO
		case 0x06, 0x11: // tcp, udp
			binary.BigEndian.PutUint16(p2[42:44], port)
			L3Packet(p2).ComputeChecksums()
			return L3Packet(p2)
		}
	}
	return nil
}

// GetNatInfo returns information about source & dest without performing any memory copy
// GetNatInfo returns information about source & destination addresses without performing any memory copy.
// This is useful for NAT implementations that need to access and potentially modify this information.
// The first return value contains IP address information, and the second contains protocol-specific information.
func (p L3Packet) GetNatInfo() ([]byte, []byte) {
	switch (p[0] >> 4) & 0xf {
	case 4: // ipv4 → p[12:20] (src, dst)
		switch p[9] {
		case 0x01: // icmp
			ip_header_size := int(p[0]&0xf) << 2
			return p[12:20], p[ip_header_size+4 : ip_header_size+6] // for ping request/ping reply
		case 0x06, 0x11: // tcp, udp
			ip_header_size := int(p[0]&0xf) << 2
			return p[12:20], p[ip_header_size : ip_header_size+4]
		default:
			return p[12:20], nil
		}
	case 6: // ipv6 → p[8:40] (src, dst)
		switch p[6] {
		case 0x06, 0x11: // tcp, udp
			return p[8:40], p[40:44]
		case 58: // icmp6
			return p[8:40], p[44:46] // for ping request/ping reply
		default:
			return p[8:40], nil
		}
	}
	return nil, nil
}

// GetSourceIP returns the source IP address from the packet.
// Works with both IPv4 and IPv6 packets, returning the appropriate net.IP type.
func (p L3Packet) GetSourceIP() net.IP {
	ip_type := (p[0] >> 4) & 0xf

	switch ip_type {
	case 4:
		return net.IP(p[12:16])
	case 6:
		return net.IP(p[8:24])
	default:
		return nil
	}
}

// GetDestinationIP returns the destination IP address from the packet.
// Works with both IPv4 and IPv6 packets, returning the appropriate net.IP type.
func (p L3Packet) GetDestinationIP() net.IP {
	ip_type := (p[0] >> 4) & 0xf

	switch ip_type {
	case 4:
		return net.IP(p[16:20])
	case 6:
		return net.IP(p[24:40])
	default:
		return nil
	}
}

// GetEthertype returns the protocol identifier for this IP packet.
// Returns ProtoIPv4 or ProtoIPv6 based on the IP version in the packet.
func (p L3Packet) GetEthertype() Protocol {
	ip_type := (p[0] >> 4) & 0xf

	switch ip_type {
	case 4:
		return ProtoIPv4
	case 6:
		return ProtoIPv6
	default:
		return 0 // Unknown protocol
	}
}

// GetProtocol returns the Layer 4 protocol identifier from the IP header.
// For IPv4, this is the Protocol field (byte 9).
// For IPv6, this is the Next Header field (byte 6).
func (p L3Packet) GetProtocol() L4Proto {
	ip_type := (p[0] >> 4) & 0xf

	switch ip_type {
	case 4:
		return L4Proto(p[9])
	case 6:
		return L4Proto(p[6])
	default:
		return 0 // Unknown protocol
	}
}

// GetSourcePort extracts the source port from TCP or UDP packets.
// Returns 0 if the packet is not TCP or UDP, or if the IP version is unknown.
// Works with both IPv4 and IPv6 packets by correctly calculating header sizes.
func (p L3Packet) GetSourcePort() uint16 {
	// read source port from tcp/udp frame, returns zero in case of error
	ip_type := (p[0] >> 4) & 0xf
	var ip_header_size int

	switch ip_type {
	case 4:
		switch p[9] {
		case 0x06: // tcp
		case 0x11: // udp
		default:
			return 0 // not tcp/udp → no port number
		}
		ip_header_size = int(p[0]&0xf) * 4
	case 6:
		switch p[6] {
		case 0x06: // tcp
		case 0x11: // udp
		default:
			return 0 // not tcp/udp → no port number
		}
		ip_header_size = 40 // ipv6 header fixed length
	default:
		return 0
	}

	// udp/tcp will always have source port first. If protocol is something else result is undefined
	return uint16(p[ip_header_size])<<8 | uint16(p[ip_header_size+1])
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
// For L3Packet, this simply returns the packet data as a byte slice.
func (p L3Packet) MarshalBinary() ([]byte, error) {
	return p, nil
}

// encode implements the Frame interface.
// For L3Packet, this appends the packet data to the provided byte slice.
func (p L3Packet) encode(b []byte) ([]byte, error) {
	return append(b, p...), nil
}

// String returns a human-readable representation of the packet,
// showing the protocol, source IP, and destination IP.
func (p L3Packet) String() string {
	return fmt.Sprintf("L3 Packet proto=%s %s => %s", p.GetProtocol(), p.GetSourceIP(), p.GetDestinationIP())
}

// Dup creates a deep copy of the packet.
// This is useful when you need to modify a packet without affecting the original.
func (p L3Packet) Dup() L3Packet {
	p2 := make([]byte, len(p))
	copy(p2, p)
	return L3Packet(p2)
}
