package rawnet

type adaptL2 struct {
	L3Device
}

func (a *adaptL2) HandleL2Packet(src L2Device, pkt L2Packet) error {
	ethertype, vlan, l3p := pkt.GetL3Packet()
	if vlan != 0 {
		// ignore packets sent with a vlan tag
		return nil
	}

	return a.L3Device.HandleL3Packet(ethertype, l3p)
}
