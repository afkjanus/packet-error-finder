package packetsAndErrors

import "github.com/google/gopacket"

// PacketAndPosition is a structure which contains a pointer to a packet, and it's position in a record.
//
//	packet		*gopacket.Packet	- a pointer to a packet
//	position 	int					- the position of the packet
type PacketAndPosition struct {
	packet   *gopacket.Packet
	position int
}

// Packet is a public getter function for the private packet field of the PacketAndPosition structure
func (packetAndPosition *PacketAndPosition) Packet() *gopacket.Packet {
	return packetAndPosition.packet
}

// Position is a public getter function for the private position field of the PacketAndPosition structure
func (packetAndPosition *PacketAndPosition) Position() int {
	return packetAndPosition.position
}
