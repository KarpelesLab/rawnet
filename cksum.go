package rawnet

func (p L3Packet) ComputeChecksums() {
	// compute ipv4 header checksum and tcp/udp/icmp/etc checksums

	switch (p[0] >> 4) & 0xf {
	case 4: // IPv4
		ip_header_size := int(p[0]&0xf) << 2
		// set to zero
		p[10] = 0
		p[11] = 0
		s := netChecksum(p[:ip_header_size]) // compute
		// wirte
		p[10] ^= byte(s)
		p[11] ^= byte(s >> 8)

		switch p[9] {
		case 0x06: // tcp
		case 0x11: // udp
			// fake ipv4 header + data
			udpLen := uint16(len(p) - ip_header_size)
			udp := p[ip_header_size:]
			udp[6] = 0
			udp[7] = 0
			cksumData := [][]byte{
				p[12:20], // source, destination
				[]byte{0, p[9], byte(udpLen), byte(udpLen >> 8)},
				udp,
			}
			s = netChecksumA(cksumData)
			udp[6] ^= byte(s)
			udp[7] ^= byte(s >> 8)
		}
	case 6: // IPv6
	}
}

// ipv4 header checksum is a checksum of the header part
func (p L3Packet) doIPv4checksum() {
	// first, set to zero
	p[10] = 0
	p[11] = 0
	ip_header_size := int(p[0]&0xf) << 2
	s := netChecksum(p[:ip_header_size])

	// write checksum
	p[10] ^= byte(s)
	p[11] ^= byte(s >> 8)
}

// netChecksum implements a common method for checksum calculation
func netChecksum(b []byte) uint16 {
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return ^uint16(s)
}

func netChecksumA(ba [][]byte) uint16 {
	s := uint32(0)

	for _, b := range ba {
		csumcv := len(b) - 1 // checksum coverage
		for i := 0; i < csumcv; i += 2 {
			s += uint32(b[i+1])<<8 | uint32(b[i])
		}
		if csumcv&1 == 0 {
			// this should be the last one
			s += uint32(b[csumcv])
		}
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return ^uint16(s)
}
