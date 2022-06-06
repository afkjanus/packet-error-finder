package packetsAndErrors

import (
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// MatchedPackets is a structure to hold foremost a slice containing the pointers to matched packets.
//
//	packets        		*Packets					- a pointer to a Packets struct
//													  with the packets from two sides that should be matched
//	matchedPackets 		[]*PacketAndPositionTuple	- a slice containing pointers to the matched packets,
//													  each tuple is one match
//	statusChan			chan int					- a channel to transfer the index
//													  of the currently matched packet for status updates
//	chansToGetStatus	[]chan int					- other parts of the software can register for status updates
//													  via a channel, these channels are stored here
type MatchedPackets struct {
	packets        *Packets
	matchedPackets []*PacketAndPositionTuple

	statusChan       chan int // just for telling the status of the packet matching to other parts of the program
	chansToGetStatus []chan int
}

// Packets is a public getter function for the packets field of a MatchedPackets structure.
func (matchedPackets *MatchedPackets) Packets() *Packets {
	return matchedPackets.packets
}

//MatchedPackets is a public getter funciton for the matchedPackets field of a MatchedPackets structure.
func (matchedPackets *MatchedPackets) MatchedPackets() []*PacketAndPositionTuple {
	return matchedPackets.matchedPackets
}

// NewMatchedPackets is a constructor for the MatchedPackets struct.
// Call MatchPackets to match the packets.
//
// Takes:
//	packets			*Packets	- a pointer to a Packets struct as cointaining the packets to match
//	flowDirection	int8		- the flow direction of the packets, eiter left to right (0) or right to left (1)
//
// Returns:
//	matchedPacketsPointer	*MatchedPackets	- a pointer to the MatchedPackets structure, the packets aren't matched
//	err						error			- the error if one appears, nil if not
func NewMatchedPackets(packets *Packets, flowDirection int8) (matchedPacketsPointer *MatchedPackets, err error) {
	// create the status channel, it shouldn't block,
	// so it should be long enough to hold all values it will get at the same time
	var statusChanLength int
	if flowDirection == FlowLeftToRight {
		statusChanLength = len(packets.leftPackets)
	} else if flowDirection == FlowRightToLeft {
		statusChanLength = len(packets.rightPackets)
	} else {
		err = errors.New("no flow direction given")
		return
	}

	// create the structure, no packets are matched
	matchedPackets := MatchedPackets{
		packets:          packets,
		statusChan:       make(chan int, statusChanLength),
		chansToGetStatus: make([]chan int, 0),
	}

	// return the pointer to the created struct
	matchedPacketsPointer = &matchedPackets
	return
}

// MatchPackets is a public function which matches the packets.
// The matched and unmatched packets can be found in the MatchedPackets field of the MatchedPackets struct.
// Unmatched packets will have a nil value at the other side of the tuple.
//
// Operates on:
//	matchedPackets	*MatchedPackets	- the MatchedPackets struct of which the packets should get matched,
//									  after this function it will include the matched packets
//									  in the MatchedPackets field
// Takes:
//	layer			int8	- the layer at which the packets should match
//	flowDirection 	int8	- the flow direction of the packets
//
// Returns:
//	numberOfReorderedPackets	int64	- the number how many packets got reordered
//	err							error	- the error if one appears, nil if not
func (matchedPackets *MatchedPackets) MatchPackets(
	layer int8,
	flowDirection int8,
) (numberOfReorderedPackets int64, err error) {
	possibleLeftMatchesWg := sync.WaitGroup{}
	possibleRightMatchesWg := sync.WaitGroup{}

	// create slices for the packets and their possible matches in parallel
	// search the possible matches later
	possibleLeftMatchesSliceChan := make(chan []*PacketAndPossibleMatches)
	possibleRightMatchesSliceChan := make(chan []*PacketAndPossibleMatches)
	go func() {
		possibleLeftMatchesSliceChan <- newPacketAndPossibleMatchesSlice(matchedPackets.packets.leftPackets)
	}()
	go func() {
		possibleRightMatchesSliceChan <- newPacketAndPossibleMatchesSlice(matchedPackets.packets.rightPackets)
	}()
	possibleLeftMatches := <-possibleLeftMatchesSliceChan
	possibleRightMatches := <-possibleRightMatchesSliceChan

	// sort the main packetAndPossibleMatchesSlices on their position in case something got out of order
	sort.SliceStable(possibleLeftMatches, func(i, j int) bool {
		return possibleLeftMatches[i].packet.position < possibleLeftMatches[j].packet.position
	})
	sort.SliceStable(possibleRightMatches, func(i, j int) bool {
		return possibleRightMatches[i].packet.position < possibleRightMatches[j].packet.position
	})

	// create hash maps containing all packets and possible matches based on the source and destination address
	// and the payload
	// create the maps parallel
	leftHashMapChan := make(chan map[uint64][]*PacketAndPossibleMatches, 1)
	leftErrChan := make(chan error, 1)
	rightHashMapChan := make(chan map[uint64][]*PacketAndPossibleMatches, 1)
	rightErrChan := make(chan error, 1)
	go func() {
		defer close(leftErrChan)
		hashMap, err := hashMappingPacketsAndPossibleMatchesSlice(possibleLeftMatches, layer) // map creation
		if err != nil {
			leftErrChan <- err
			return
		}
		leftHashMapChan <- hashMap
	}()
	go func() {
		defer close(rightErrChan)
		hashMap, err := hashMappingPacketsAndPossibleMatchesSlice(possibleRightMatches, layer) // map creation
		if err != nil {
			rightErrChan <- err
			return
		}
		rightHashMapChan <- hashMap
	}()
	for e := range leftErrChan {
		err = e
		return
	}
	for e := range rightErrChan {
		err = e
		return
	}
	possibleLeftMatchesMap := <-leftHashMapChan
	possibleRightMatchesMap := <-rightHashMapChan

	// search for possible matches for every packet in parallel with the help of the created hash map
	// the possible matches will be added to the possibleMatches field of each PacketAndPossibleMatches struct
	leftErrChan = make(chan error, len(possibleLeftMatches)) // len(possibleLeftMatches) errors can occur parallel
	for _, packet := range possibleLeftMatches {
		possibleLeftMatchesWg.Add(1)

		go func(packet *PacketAndPossibleMatches) {
			defer possibleLeftMatchesWg.Done()
			// possible candidates for a match are only those packets with the same hash
			packetHash, err := hashSrcDstPayloadBytes(*packet.packet.packet, layer)
			if err != nil {
				leftErrChan <- err
				return
			}
			packet.searchPossibleMatches( // search
				possibleRightMatchesMap[packetHash],
				layer,
			)
		}(packet)
	}

	rightErrChan = make(chan error, len(possibleRightMatches)) // len(possibleRightMatches) errors can occur parallel
	for _, packet := range possibleRightMatches {
		possibleRightMatchesWg.Add(1)

		go func(packet *PacketAndPossibleMatches) {
			defer possibleRightMatchesWg.Done()
			// possible candidates for a match are only those packets with the same hash
			packetHash, err := hashSrcDstPayloadBytes(*packet.packet.packet, layer)
			if err != nil {
				rightErrChan <- err
				return
			}
			packet.searchPossibleMatches( // search
				possibleLeftMatchesMap[packetHash],
				layer,
			)
		}(packet)
	}

	go func() {
		// wait for all possible matches to be found
		possibleLeftMatchesWg.Wait()
		possibleRightMatchesWg.Wait()

		// close the error channels to signal that no errors will occur anymore and to let the program go on
		close(leftErrChan)
		close(rightErrChan)
	}()

	// check if an error occurred and sync with the wait-group of which are waiting in the goroutine above
	for e := range leftErrChan {
		err = e
		return
	}
	for e := range rightErrChan {
		err = e
		return
	}

	// sort the possible matches inside the PacketAndPossibleMatches structs,
	// so they are in order of their positions
	for _, packet := range possibleLeftMatches {
		sort.SliceStable(packet.possibleMatches, func(i, j int) bool {
			return packet.possibleMatches[i].packet.position < packet.possibleMatches[j].packet.position
		})
	}
	for _, packet := range possibleRightMatches {
		sort.SliceStable(packet.possibleMatches, func(i, j int) bool {
			return packet.possibleMatches[i].packet.position < packet.possibleMatches[j].packet.position
		})
	}

	// search the best match for each packet and add those to the matchedPackets field in the matchedPackets structure
	numberOfReorderedPackets, err = matchedPackets.searchBestMatches(
		&possibleLeftMatches,
		&possibleRightMatches,
		flowDirection,
	)

	// packets got matched return
	return
}

// searchBestMatches is a private function to search the best matches for each packet and adds the matched
// and unmatched packets to matchedPackets slice of the MatchedPackets structure.
//
// Operates on:
//	matchedPackets	*MatchedPackets	- the MatchedPackets structure where the matchedPackets field will be filled
//
// Takes:
//	possibleLeftMatches		*[]*PacketAndPossibleMatches	- packets and their possible matches from the records
//															  of the left side
//	possibleRightMatches	*[]*PacketAndPossibleMatches	- packets and their possible matches from the records
//															  of the right side
//
// Returns:
//	flowDirection 			int8							- the flow direction of the packets
//	err						error							- the error if one appears, nil if not
func (matchedPackets *MatchedPackets) searchBestMatches(
	possibleLeftMatches *[]*PacketAndPossibleMatches,
	possibleRightMatches *[]*PacketAndPossibleMatches,
	flowDirection int8,
) (numberOfReorderedPackets int64, err error) {
	// create a slice to store the positions of the reordered packets
	reorderedPackets := make([]int, 0, 100)

	// create slices to store unmatched packets, foremost to count them
	unmatchedLeftPackets := make([]*PacketAndPosition, 0)
	unmatchedRightPackets := make([]*PacketAndPosition, 0)

	// start the reporting of the progress of the packet matching
	matchedPackets.startStatusUpdate()
	defer close(matchedPackets.statusChan)

	// check the flow direction, the same function is implemented for both flow directions
	// to lower code complexity, especially in the if queries, the algorithm is implemented for both sides
	if flowDirection == FlowLeftToRight {
		// match each packet
		for _, leftPacket := range *possibleLeftMatches {
			matchedPackets.statusChan <- leftPacket.packet.position // report the status

			// check if there are packets on the right (receiver) side, which can't be matched and add them as unmatched
			// either because they have no possible match, or they were received before the next packet was sent
			for len(*possibleRightMatches) != 0 && ((*possibleRightMatches)[0].packet.position+len(unmatchedLeftPackets)+len(reorderedPackets) < leftPacket.packet.position+len(unmatchedRightPackets) || len((*possibleRightMatches)[0].possibleMatches) == 0) {
				rightPacket := (*possibleRightMatches)[0]
				matchedPackets.matchedPackets = append(matchedPackets.matchedPackets, &PacketAndPositionTuple{
					left:  nil,
					right: rightPacket.packet,
				})
				unmatchedRightPackets = append(unmatchedRightPackets, rightPacket.packet)
				removeFirstPacketFromPacketAndPossibleMatchesSlice(possibleRightMatches)
			}

			sort.Ints(reorderedPackets) // sort the reordered packets,
			// because otherwise the following for will stop to early
			for len(reorderedPackets) != 0 && reorderedPackets[0]+len(unmatchedLeftPackets)+len(reorderedPackets)-1 < leftPacket.packet.position+len(unmatchedRightPackets) {
				// remove all reordered packets, which aren't relevant from now on,
				// because the sender side reached the position of the reordered packet on the receiver side
				reorderedPackets = reorderedPackets[1:]
			}

			// start the matching
			if len(leftPacket.possibleMatches) == 0 {
				// if the packet has no possible match, it is matched to nil and added to the unmatched packets
				matchedPackets.matchedPackets = append(matchedPackets.matchedPackets, &PacketAndPositionTuple{
					left:  leftPacket.packet,
					right: nil,
				})
				unmatchedLeftPackets = append(unmatchedLeftPackets, leftPacket.packet)
			} else {
				// the packet has possible matches, search the best one
				bestLeftMatch := leftPacket.checkForMatchWithSmallestDelta(
					len(unmatchedLeftPackets),
					len(unmatchedRightPackets),
					len(reorderedPackets),
				)

				if bestLeftMatch == nil {
					// there is no best match, the possible matches match better to the other packets
					matchedPackets.matchedPackets = append(matchedPackets.matchedPackets, &PacketAndPositionTuple{
						left:  leftPacket.packet,
						right: nil,
					})
					unmatchedLeftPackets = append(unmatchedLeftPackets, leftPacket.packet)
				} else {
					// match with the best match
					matchedPackets.matchedPackets = append(matchedPackets.matchedPackets, &PacketAndPositionTuple{
						left:  leftPacket.packet,
						right: bestLeftMatch.packet,
					})

					// check if reorder occurred
					if bestLeftMatch.packet.position+len(unmatchedLeftPackets)+len(reorderedPackets) > leftPacket.packet.position+len(unmatchedRightPackets) {
						reorderedPackets = append(reorderedPackets, bestLeftMatch.packet.position)
						numberOfReorderedPackets++
					}

					// remove the right packet from the slice of right packets which weren't matched until now
					removeGivenPointerFromPacketAndPossibleMatchesSlice(possibleRightMatches, bestLeftMatch)

					// remove the right packet from its other possible matches as a possible match
					for _, possibleMatch := range bestLeftMatch.possibleMatches {
						if possibleMatch != leftPacket {
							removeGivenPointerFromPacketAndPossibleMatchesSlice(&possibleMatch.possibleMatches, bestLeftMatch)
						}
					}
				}

				// remove the left packet from its other possible matches as a possible match
				for _, possibleMatch := range leftPacket.possibleMatches {
					if possibleMatch != bestLeftMatch {
						removeGivenPointerFromPacketAndPossibleMatchesSlice(&possibleMatch.possibleMatches, leftPacket)
					}
				}
			}
		}

		// all packets at the seder side were viewed
		// all packets, which are left because there weren't matched to a packet at the sender side,
		// will be added as unmatched here
		for _, rightPacket := range *possibleRightMatches {
			matchedPackets.matchedPackets = append(matchedPackets.matchedPackets, &PacketAndPositionTuple{
				left:  nil,
				right: rightPacket.packet,
			})
			unmatchedRightPackets = append(unmatchedRightPackets, rightPacket.packet)
		}

	} else if flowDirection == FlowRightToLeft {
		// match each packet
		for _, rightPacket := range *possibleRightMatches {
			matchedPackets.statusChan <- rightPacket.packet.position // report the status

			// check if there are packets on the left (receiver) side, which can't be matched and add them as unmatched
			// either because they have no possible match, or they were received before the next packet was sent
			for len(*possibleLeftMatches) != 0 && ((*possibleLeftMatches)[0].packet.position+len(unmatchedRightPackets)+len(reorderedPackets) < rightPacket.packet.position+len(unmatchedLeftPackets) || len((*possibleLeftMatches)[0].possibleMatches) == 0) {
				leftPacket := (*possibleLeftMatches)[0]
				matchedPackets.matchedPackets = append(matchedPackets.matchedPackets, &PacketAndPositionTuple{
					left:  leftPacket.packet,
					right: nil,
				})
				unmatchedLeftPackets = append(unmatchedLeftPackets, leftPacket.packet)
				removeFirstPacketFromPacketAndPossibleMatchesSlice(possibleLeftMatches)
			}

			sort.Ints(reorderedPackets) // sort the reordered packets,
			// because otherwise the following for will stop to early
			for len(reorderedPackets) != 0 && reorderedPackets[0]+len(unmatchedRightPackets)+len(reorderedPackets)-1 < rightPacket.packet.position+len(unmatchedLeftPackets) {
				// remove all reordered packets, which aren't relevant from now on,
				// because the sender side reached the position of the reordered packet on the receiver side
				reorderedPackets = reorderedPackets[1:]
			}

			// start the matching
			if len(rightPacket.possibleMatches) == 0 {
				// if the packet has no possible match, it is matched to nil and added to the unmatched packets
				matchedPackets.matchedPackets = append(matchedPackets.matchedPackets, &PacketAndPositionTuple{
					left:  nil,
					right: rightPacket.packet,
				})
				unmatchedRightPackets = append(unmatchedRightPackets, rightPacket.packet)
			} else {
				// the packet has possible matches, search the best one
				bestRightMatch := rightPacket.checkForMatchWithSmallestDelta(len(unmatchedRightPackets), len(unmatchedLeftPackets), len(reorderedPackets))

				if bestRightMatch == nil {
					// there is no best match, the possible matches match better to other packets
					matchedPackets.matchedPackets = append(matchedPackets.matchedPackets, &PacketAndPositionTuple{
						left:  nil,
						right: rightPacket.packet,
					})
					unmatchedRightPackets = append(unmatchedRightPackets, rightPacket.packet)
				} else {
					// match with the best match
					matchedPackets.matchedPackets = append(matchedPackets.matchedPackets, &PacketAndPositionTuple{
						left:  bestRightMatch.packet,
						right: rightPacket.packet,
					})

					// check if reorder occurred
					if bestRightMatch.packet.position+len(unmatchedRightPackets)+len(reorderedPackets) > rightPacket.packet.position+len(unmatchedLeftPackets) {
						reorderedPackets = append(reorderedPackets, bestRightMatch.packet.position)
						numberOfReorderedPackets++
					}

					// remove the left packet from the slice of left packets which weren't matched until now
					removeGivenPointerFromPacketAndPossibleMatchesSlice(possibleLeftMatches, bestRightMatch)

					// remove the left packet from its other possible matches as a possible match
					for _, possibleMatch := range bestRightMatch.possibleMatches {
						if possibleMatch != rightPacket {
							removeGivenPointerFromPacketAndPossibleMatchesSlice(
								&possibleMatch.possibleMatches,
								bestRightMatch,
							)
						}
					}
				}

				// remove the right packet from its other possible matches as a possible match
				for _, possibleMatch := range rightPacket.possibleMatches {
					if possibleMatch != bestRightMatch {
						removeGivenPointerFromPacketAndPossibleMatchesSlice(&possibleMatch.possibleMatches, rightPacket)
					}
				}
			}
		}

		// all packets at the seder side were viewed
		// all packets which are left because there weren't matched to a packet at the sender side
		// will be added as unmatched here
		for _, leftPacket := range *possibleLeftMatches {
			matchedPackets.matchedPackets = append(matchedPackets.matchedPackets, &PacketAndPositionTuple{
				left:  leftPacket.packet,
				right: nil,
			})
			unmatchedLeftPackets = append(unmatchedLeftPackets, leftPacket.packet)
		}
	} else {
		err = errors.New("no flow direction given while searching best match")
		return
	}

	// cut all duplicate and unmatched packets at the start of the matched packets
	// they could be there because the recording wasn't started at the same time
	for matchedPackets.matchedPackets[0].left == nil || matchedPackets.matchedPackets[0].right == nil {
		matchedPackets.matchedPackets = matchedPackets.matchedPackets[1:]
	}

	// cut all duplicate and unmatched packets at the end of the matched packets
	// they could be there because the recording wasn't stopped at the same time
	for matchedPackets.matchedPackets[len(matchedPackets.matchedPackets)-1].left == nil || matchedPackets.matchedPackets[len(matchedPackets.matchedPackets)-1].right == nil {
		matchedPackets.matchedPackets = matchedPackets.matchedPackets[:len(matchedPackets.matchedPackets)-2]
	}

	return
}

// RegisterForStatusUpdate is a public function which can be used to register a channel
// from another part of the program that should receive status updates of the current progress of the
// packet matching.
//
// Operates on:
//	matchedPackets	*MatchedPackets	- a pointer to the MatchedPackets structure which should report the status
//
// Takes:
//	chanToRegister	chan int	- the channel to register
//
// Returns:
//	error	- returns nil if the channel is registered and an error describing the registration problem if the
//			  registration wasn't possible
func (matchedPackets *MatchedPackets) RegisterForStatusUpdate(chanToRegister chan int) error {
	// check if the capacity of the provided channel is big enough
	if cap(chanToRegister) < cap(matchedPackets.statusChan) {
		// capacity is not big enough -> return an error
		var errorStringBuilder strings.Builder
		errorStringBuilder.WriteString("the capacity of the given chan is to small, it has to be at least ")
		errorStringBuilder.WriteString(strconv.Itoa(cap(matchedPackets.statusChan)))
		errorStringBuilder.WriteString(" but is ")
		errorStringBuilder.WriteString(strconv.Itoa(cap(chanToRegister)))
		return errors.New(errorStringBuilder.String())
	}

	// register the channel
	matchedPackets.chansToGetStatus = append(matchedPackets.chansToGetStatus, chanToRegister)
	return nil
}

// GetCapacityForStatusUpdateChan is a public function to get the minimum capacity of an channel that can be registered
// for via the RegisterForStatusUpdate function.
//
// Operates on:
//	matchedPackets	*MatchedPackets	- a pointer to a MatchedPackets structure of which the needed minimum capacity
//									  should be evaluated
// Returns:
// int	- the minimum capacity
func (matchedPackets *MatchedPackets) GetCapacityForStatusUpdateChan() int {
	return cap(matchedPackets.statusChan)
}

// startStatusUpdate is a private function to start the reporting of the status.
// It will stop reporting when the statusChan of the MatchedPackets structure will be closed.
// It is non-blocking. Even blocking of channels reporting to won't block the reporting to other channels.
//
// Operates on:
//	matchedPackets	*MatchedPackets	- a pointer to a MatchedPackets structure that should stat reporting its
//									  matching status
func (matchedPackets *MatchedPackets) startStatusUpdate() {
	go func() { // report in the background
		for currentStatus := range matchedPackets.statusChan { // report while the statusChan is open
			for _, chanToGetStatus := range matchedPackets.chansToGetStatus { // report to each registered channel
				select {
				case chanToGetStatus <- currentStatus: // it is possible to send the value to the chan
				default: // it isn't possible to send the value to the chan, the chan is full, do nothing
				}
			}
		}

		// reporting is over, close all registered channels
		for _, chanToGetUpdate := range matchedPackets.chansToGetStatus {
			close(chanToGetUpdate)
		}
	}()
}
