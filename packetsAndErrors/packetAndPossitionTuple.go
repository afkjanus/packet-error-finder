package packetsAndErrors

// PacketAndPositionTuple is a structure that contains to PacketAndPosition structures
//
//	left  *PacketAndPosition	- a pointer to the left PacketAndPosition structure of the tuple
//	right *PacketAndPosition	- a pointer to the right PacketAndPosition structure of the tuple
type PacketAndPositionTuple struct {
	left  *PacketAndPosition
	right *PacketAndPosition
}

// Left is a public getter function for the private left field of the PacketAndPositionTuple structure
func (packetAndPositionTuple *PacketAndPositionTuple) Left() *PacketAndPosition {
	return packetAndPositionTuple.left
}

// Right is a public getter function for the private right field of the PacketAndPositionTuple structure
func (packetAndPositionTuple *PacketAndPositionTuple) Right() *PacketAndPosition {
	return packetAndPositionTuple.right
}
