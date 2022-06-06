package packetsAndErrors

import (
	"errors"
	"github.com/cespare/xxhash/v2"
	"github.com/google/gopacket"
	"math"
	"sync"
)

// PacketAndPossibleMatches is a structure that contains a packet, and its possible matches.
//
//	packet         	*PacketAndPosition			- a pointer to a packet
//	possibleMatches	[]*PacketAndPossibleMatches	- a slice of pointers to possible matches of this packet
type PacketAndPossibleMatches struct {
	packet          *PacketAndPosition
	possibleMatches []*PacketAndPossibleMatches
}

// Packet is a public getter function for the private packet field of the PacketAndPossibleMatches structure
func (packetAndPossibleMatches *PacketAndPossibleMatches) Packet() *PacketAndPosition {
	return packetAndPossibleMatches.packet
}

// PossibleMatches is a public getter function for the private possibleMatches field
// of the PacketAndPossibleMatches structure
func (packetAndPossibleMatches *PacketAndPossibleMatches) PossibleMatches() []*PacketAndPossibleMatches {
	return packetAndPossibleMatches.possibleMatches
}

// searchPossibleMatches is a private function to search all packets which could be a match to another packet.
//
// Operates on:
//	packetAndPossibleMatches	*PacketAndPossibleMatches	- a pointer to a PacketAndPossibleMatches structure
//															  to search the possible matches for
//															  the possible matches will be added to the
//															  possibleMatches field
// Takes:
//	candidates	[]*PacketAndPossibleMatches	- a slice of pointers to PacketAndPossibleMatches that could be
//											  possible matches of the packet operated on, most of the time
//											  all packets from the record of the other side with the same hash
//	layer		int8						- the layer where the packets should possibly match, either 2 for
//											  the link ISO/OSI layer or 3 for the network layer
func (packetAndPossibleMatches *PacketAndPossibleMatches) searchPossibleMatches(
	candidates []*PacketAndPossibleMatches,
	layer int8,
) {
	// set up datastructures for parallelism
	possibleMatchesChan := make(chan *PacketAndPossibleMatches)
	wg := sync.WaitGroup{}

	// evaluate if the candidates could be possible matches in parallel
	wg.Add(len(candidates))
	for _, candidate := range candidates {
		go func(candidate *PacketAndPossibleMatches) {
			defer wg.Done()

			// a packet is a possible match, if they are equal on the specified layer
			if equalPacket(*packetAndPossibleMatches.packet.packet, *candidate.packet.packet, layer) {
				possibleMatchesChan <- candidate // equal -> return the candidate as possible match
			}
		}(candidate)
	}

	// wait for all candidates to be evaluated and close the channel afterwards
	// to signal, that there won't be any other possible matches
	go func() {
		wg.Wait()
		close(possibleMatchesChan)
	}()

	// add the possible matches of the packet to the packetAndPossibleMatches
	for possibleMatch := range possibleMatchesChan {
		packetAndPossibleMatches.possibleMatches = append(packetAndPossibleMatches.possibleMatches, possibleMatch)
	}
}

// packetAndPossibleMatches is a private function to search the match with the smallest delta in a
// PacketAndPossibleMatches struct. It needs the number of unmatched packets from the side of the
// PacketAndPossibleMatches struct and the other side.
// If the method is called from outside the firstRun bool can be set to true, there is no need to set the firstRun bool.
// If there is a call from outside the firstRun bool shouldn't be set to false, otherwise there will be no check if
// there are better matches for the possible best match.
// The PacketAndPossibleMatches struct with the smallest delta to the given PacketAndPossibleMatches struct,
// which has no better matches, will be returned.
func (packetAndPossibleMatches *PacketAndPossibleMatches) checkForMatchWithSmallestDelta(
	numberOfUnmatchedPacketsOwnSide int,
	numberOfUnmatchedPacketsOtherSide int,
	numberOfReorderedPackets int,
	firstRun ...bool,
) (bestPossibleMatch *PacketAndPossibleMatches) {
	// if there is only one possible match and the packets have the same position, match them
	// otherwise check the delta (maybe the packet was received before it was sent)
	if (len(firstRun) == 0 || firstRun[0] == true) && len(packetAndPossibleMatches.possibleMatches) == 1 && packetAndPossibleMatches.packet.position+numberOfUnmatchedPacketsOtherSide == packetAndPossibleMatches.possibleMatches[0].packet.position+numberOfUnmatchedPacketsOwnSide+numberOfReorderedPackets {
		bestPossibleMatch = packetAndPossibleMatches.possibleMatches[0]
		return
	}

	deltaPacketBestPossibleMatch := math.MaxFloat64 // the smallest delta between the left packet
	// and one of the possible matches
	bestPossibleMatch = nil

	for _, possibleMatch := range packetAndPossibleMatches.possibleMatches { // the possible match is from the right packets
		var delta float64
		// calculate the delta
		// depending on the run, the reordered packets have to be added to the possible match, or the packet itself
		if len(firstRun) == 0 || firstRun[0] == true {
			delta = float64(possibleMatch.packet.position + numberOfUnmatchedPacketsOwnSide + numberOfReorderedPackets - (packetAndPossibleMatches.packet.position + numberOfUnmatchedPacketsOtherSide))
		} else {
			delta = float64(possibleMatch.packet.position + numberOfUnmatchedPacketsOwnSide - (packetAndPossibleMatches.packet.position + numberOfUnmatchedPacketsOtherSide + numberOfReorderedPackets))
		}
		// the delta is calculated based on the position of the possible match
		// the number of unmatched packets from the packet side gets added, because these packets are missing on the side of the possible matches
		// the number of reordered packets gets added, because they are moving the possible matches up (first run)
		// the position of the packet gets subtracted (delta)
		// the number of unmatched packets from the side of the possible matches gets added to the own side, because these packets are missing on the onw side
		// the number of reordered packets gets added to the own side, because they are moving the own side up (second run)
		// the number of reordered packets can be different from the real number of reordered packets, especially if the delta gets bigger,
		// the measurement gets fuzzy if the delta gets bigger, this should be a minor problem, because small deltas are prefered

		// if the packet was received before it was sent ( negative delta in the first run, positive in the second)
		// it can't be a possible match
		if delta < 0 && (len(firstRun) == 0 || firstRun[0] == true) {
			continue
		} else if delta > 0 && (len(firstRun) != 0 && firstRun[0] == false) {
			continue
		}

		// if the new delta is smaller than the actual smallest delta
		// and the possible match matches the packet with the smallest delta too,
		// there is a new best possible match and a new smallest delta
		if delta < deltaPacketBestPossibleMatch {
			if len(firstRun) == 0 || firstRun[0] == true {
				// check if the possible match has better matches, but just one time, not for the possible matches of the possible matches ...
				if possibleMatch.checkForMatchWithSmallestDelta(numberOfUnmatchedPacketsOtherSide, numberOfUnmatchedPacketsOwnSide, numberOfReorderedPackets, false) == packetAndPossibleMatches {
					bestPossibleMatch = possibleMatch
					deltaPacketBestPossibleMatch = delta
				}
			} else {
				bestPossibleMatch = possibleMatch
				deltaPacketBestPossibleMatch = delta
			}
		}
	}

	return
}

// newPacketAndPossibleMatchesSlice is a private function to create a slice of PacketAndPossibleMatches
// structures from a packet slice, the possible matches will be nil
//
// Takes:
//	packets	[]gopacket.Packet	- a slice of packets which will be used for the creation of the PacketAndPossibleMatches
//								  struct. The index of the packet in the slice will be the packet position
// Returns:
//	possibleMatches	[]*PacketAndPossibleMatches	- a pointer to the created PacketAndPossibleMatches slice
func newPacketAndPossibleMatchesSlice(packets []gopacket.Packet) (possibleMatches []*PacketAndPossibleMatches) {
	possibleMatches = make([]*PacketAndPossibleMatches, 0, len(packets))
	for packetPosition := range packets {
		packet := &packets[packetPosition]
		possibleMatches = append(possibleMatches, &PacketAndPossibleMatches{
			packet: &PacketAndPosition{
				packet:   packet,
				position: packetPosition,
			},
			possibleMatches: nil,
		})
	}

	return
}

// removeGivenPointerFromPacketAndPossibleMatchesSlice is a function to remove a PacketAndPossibleMatches pointer
// from a slice of PacketAndPossibleMatches pointers.
// The changed slice is returned as a side effect.
// Removes only the first occurrence of the given PacketAndPossibleMatches pointer.
//
// Takes:
//	packets	*[]*PacketAndPossibleMatches	- a pointer to a slice of PacketAndPossibleMatches pointers
//											  from which the pointer to the PacketAndPossibleMatched should be removed
//	packet	*PacketAndPossibleMatches		- a pointer to a PacketAndPossibleMatches which should be removed from the
//											  slice, it won't be changed
func removeGivenPointerFromPacketAndPossibleMatchesSlice(
	packets *[]*PacketAndPossibleMatches,
	packet *PacketAndPossibleMatches,
) {
	if packet == nil {
		return
	}
	for candidatePosition, candidate := range *packets {
		if candidate == packet {
			*packets = append((*packets)[:candidatePosition], (*packets)[candidatePosition+1:]...)
			return
		}
	}
}

// removeFirstPacketFromPacketAndPossibleMatchesSlice is a private function to remove the first packet from a slice of
// PacketAndPossibleMatches pointers. The changed slice is returned as a side effect on the old slice.
//
// Takes:
//	packets	*[]*PacketAndPossibleMatches	- a pointer to a PacketAndPossibleMatches slice
//											  the slice will be changed
func removeFirstPacketFromPacketAndPossibleMatchesSlice(packets *[]*PacketAndPossibleMatches) {
	*packets = (*packets)[1:]
}

// hashMappingPacketsAndPossibleMatchesSlice is a private function to create a hash map
// from a slice of PacketAndPossibleMatches pointers. Collisions are handled using chaining.
//
// Takes:
//	packets	[]*PacketAndPossibleMatches	- a slice of pointers to PacketAndPossibleMatches which should be added
//										  to a hash map
//	layer	int8						- the network layer on which should be hashed
//
// Returns:
//	map[uint64][]*PacketAndPossibleMatches	- a hash map containing all the PacketAndPossibleMatches in slices
//											  of packets with the same hash
//	error									- the error if one appears, nil if not
func hashMappingPacketsAndPossibleMatchesSlice(
	packets []*PacketAndPossibleMatches,
	layer int8,
) (map[uint64][]*PacketAndPossibleMatches, error) {
	// create an empty hash map
	hashMap := make(map[uint64][]*PacketAndPossibleMatches)

	// hash every packet
	for _, packet := range packets {
		hash, err := hashSrcDstPayloadBytes(*packet.packet.packet, layer) // create the hash
		if err != nil {
			return nil, err
		}

		slice, exists := hashMap[hash] // check if a collision occurred
		if exists {                    // collision, slice already exists append to the slice
			slice = append(slice, packet)
			hashMap[hash] = slice
		} else { // no collision, create new slice
			hashMap[hash] = []*PacketAndPossibleMatches{packet}
		}
	}

	return hashMap, nil
}

// hashSrcDstPayloadBytes is a private function to create the hash of packet on a specific layer.
//
// Takes:
//	packet	gopacket.Packet	- the packet to hash
//	layer	int8			- the network layer to hash on, either layer 2 or 3
//
// Returns:
//	uint64	- the hash
//	error	- the error if one appears, nil if not
func hashSrcDstPayloadBytes(packet gopacket.Packet, layer int8) (uint64, error) {
	if layer == LinkLayer {
		return hashSrcMacDstMacPayloadBytes(packet), nil
	} else if layer == NetworkLayer {
		return hashSrcIpDstIpPayloadBytes(packet), nil
	} else {
		return 0, errors.New("only hashing on layer 2 or 3 are supported")
	}
}

// hashSrcMacDstMacPayloadBytes is private function to create the hash of a packet on network layer 2.
// The hash will be created from the source MAC address, the destination MAC address and the layer 2 payload.
//
// Takes:
//	packet	gopacket.Packet	- the packet to hash
//
// Returns:
//	uint64	- the hash
func hashSrcMacDstMacPayloadBytes(packet gopacket.Packet) uint64 {
	// get the source MAC address
	srcMacDstMacPayloadBytes := packet.LinkLayer().LinkFlow().Src().Raw()
	// get and concat the destination MAC address
	srcMacDstMacPayloadBytes = append(srcMacDstMacPayloadBytes, packet.LinkLayer().LinkFlow().Dst().Raw()...)
	// get and concat the layer 2 payload
	srcMacDstMacPayloadBytes = append(srcMacDstMacPayloadBytes, packet.LinkLayer().LayerPayload()...)

	// calculate the hash
	return xxhash.Sum64(srcMacDstMacPayloadBytes)
}

// hashSrcIpDstIpPayloadBytes is private function to create the hash of a packet on network layer 3.
// The hash will be created from the source IP address, the destination IP address and the layer 3 payload.
//
// Takes:
//	packet	gopacket.Packet	- the packet to hash
//
// Returns:
//	uint64	- the hash
func hashSrcIpDstIpPayloadBytes(packet gopacket.Packet) uint64 {
	// get the source IP address
	srcIpDstIpPayloadBytes := packet.NetworkLayer().NetworkFlow().Src().Raw()
	// get and concat the destination IP address
	srcIpDstIpPayloadBytes = append(srcIpDstIpPayloadBytes, packet.NetworkLayer().NetworkFlow().Dst().Raw()...)
	// get and concat the layer 3 payload
	srcIpDstIpPayloadBytes = append(srcIpDstIpPayloadBytes, packet.NetworkLayer().LayerPayload()...)

	// calculate the hash
	return xxhash.Sum64(srcIpDstIpPayloadBytes)
}
