package packetsAndErrors

import (
	"math"
)

// CalculateLossRate is a public function that calculates the probability for loss in
// a PacketAndPositionTuple slice of matched packets.
//
// Takes:
//	packets			[]*PacketAndPositionTuple	- a pointer to a slice of matched packets
//	flowDirection	int8						- the flow direction of the matched packets
//
// Returns:
// float64	- the probability for loss in the matched packets
func CalculateLossRate(packets []*PacketAndPositionTuple, flowDirection int8) float64 {
	lostPacketsCount := 0
	allPacketsCount := 0 // all packets without duplicates

	for _, packet := range packets { // check all packets
		if (packet.left == nil && flowDirection == FlowRightToLeft) || (packet.right == nil && flowDirection == FlowLeftToRight) {
			// loss occurs if there is no packet on the receiver side
			lostPacketsCount++
		}
		if (flowDirection == FlowLeftToRight && packet.left != nil) || (flowDirection == FlowRightToLeft && packet.right != nil) {
			// do not count the duplicates (no packet on the sender side)
			allPacketsCount++
		}
	}

	// calculate the loss probability
	return float64(lostPacketsCount) / float64(allPacketsCount)
}

// CalculateDuplicateRate is a public function that calculates the probability for duplication in
// a PacketAndPositionTuple slice of matched packets.
//
// Takes:
//	packets			[]*PacketAndPositionTuple	- a pointer to a slice of matched packets
//	flowDirection	int8						- the flow direction of the matched packets
//
// Returns:
// float64	- the probability for duplication in the matched packets
func CalculateDuplicateRate(packets []*PacketAndPositionTuple, flowDirection int8) float64 {
	duplicatePackets := 0

	for _, packet := range packets {
		if (packet.left == nil && flowDirection == FlowLeftToRight) || (packet.right == nil && flowDirection == FlowRightToLeft) {
			// Packets are duplicate if they have no match on the sender side
			duplicatePackets++
		}
	}

	// calculate the duplication probability
	return float64(duplicatePackets) / float64(len(packets)-duplicatePackets)
}

// CalculateJitter is a public function to calculates the jitter of given packets in ms.
//
// Takes:
//	packets	[]*PacketAndPositionTuple	- a pointer to a slice of matched packets
//
// Returns:
//	float64 - the loss in ms
func CalculateJitter(packets []*PacketAndPositionTuple) float64 {
	var timeDifferenceSum float64 = 0

	var smallestDifference = math.Inf(1)
	var biggestDifference float64 = 0

	for _, packet := range packets {
		if packet.left == nil || packet.right == nil { // if the packet was lost or duplicated no difference can be calculated
			continue
		}

		// the jitter is calculated in ms -> get the times in ms
		leftTime := (*packet.left.packet).Metadata().Timestamp.UnixMilli()
		rightTime := (*packet.right.packet).Metadata().Timestamp.UnixMilli()

		// get the absolute time difference
		// because of abs the direction and the direction of the difference of the 2 clocks are irrelevant
		timeDifference := math.Abs(float64(leftTime - rightTime))

		if timeDifference < smallestDifference {
			smallestDifference = timeDifference
		}
		if timeDifference > biggestDifference {
			biggestDifference = timeDifference
		}

		timeDifferenceSum += timeDifference
	}

	averageDifference := timeDifferenceSum / float64(len(packets))

	// (0 -- smallestDifference -- averageDifference -- biggestDifference -- +inf)

	jitterPossibility1 := averageDifference - smallestDifference
	jitterPossibility2 := biggestDifference - averageDifference

	if jitterPossibility1 >= jitterPossibility2 { // get the biggest jitter
		return jitterPossibility1
	} else {
		return jitterPossibility2
	}
}

// CalculateReorderRate is a public function to calculate the probability of reorder in matched packets.
//
// Takes:
//	numberOfReorderedPackets	int64						- the number of reordered packets
//	packetTuples				[]*PacketAndPositionTuple	- a slice of pointers to matched packets
func CalculateReorderRate(numberOfReorderedPackets int64, packetTuples []*PacketAndPositionTuple) float64 {
	packetsWithoutLostOrReorder := 0

	// count all matched packets
	for _, tuple := range packetTuples {
		if tuple.left != nil && tuple.right != nil {
			packetsWithoutLostOrReorder++
		}
	}

	// calculate probability for reorder
	// use the counter probability to match netem
	return 1 - (float64(numberOfReorderedPackets) / float64(packetsWithoutLostOrReorder))
}

// CalculateMarkovRates is a public function to calculate the probabilities for the simulation of loss
// with markov chains.
// State 0: good reception
// State 3: loss during good reception
// State 2: burst loss
// State 1: good reception during burst
//
// Takes:
//	packets 								[]*PacketAndPositionTuple	- a slice of pointers to matched packets
//	flowDirection 							int8						- the flow direction
//	maxNumberOfPacketsReceivedDuringBurst 	int							- the number of packets, that can be received
//																		  during a burst without changing into state 0
//
// Returns:
//	p02	float64	- probability for transition from state 0 to 2
//	p20	float64	- probability for transition from state 2 to 0
//	p12	float64	- probability for transition from state 1 to 2
//	p21	float64	- probability for transition from state 2 to 1
//	p04	float64	- probability for transition from state 0 to 3
func CalculateMarkovRates(
	packets []*PacketAndPositionTuple,
	flowDirection int8,
	maxNumberOfPacketsReceivedDuringBurst int,
) (p02, p20, p21, p12, p03 float64) {
	const (
		s0 int8 = iota // State 0: good reception
		s1             // State 1: good reception during burst
		s2             // State 2: burst loss
		s3             // State 3: loss during good reception
	)

	state := s0

	// number of packets which triggered the specific transition
	t02Packets := 0
	t20Packets := 0
	t12Packets := 0
	t21Packets := 0
	t03Packets := 0

	// number of packets which where received/lost during the specific state
	s0Packets := 0
	s1Packets := 0
	s2Packets := 0
	// s3Packets not needed, because there is only one edge from s3 to s0, the probability is 1

	numberOfPacketsReceivedDuringBurst := 0

	for _, packet := range packets {
		if (packet.left == nil && flowDirection == FlowLeftToRight) || (packet.right == nil && flowDirection == FlowRightToLeft) { // duplicate -> ignore
			continue
		}

		if (packet.left == nil && flowDirection == FlowRightToLeft) || (packet.right == nil && flowDirection == FlowLeftToRight) { // packet lost
			if state == s0 { // loss of first packet in good state, transition to s3
				s0Packets++

				t03Packets++
				state = s3
				continue
			}
			if state == s1 { // loss after good reception during burst, transition to s2
				s1Packets++

				numberOfPacketsReceivedDuringBurst = 0 // reset the counter

				t12Packets++
				state = s2
				continue
			}
			if state == s2 { // loss during burst, stay in s2
				s2Packets++

				state = s2
				continue
			}
			if state == s3 { // loss after loss in good state, not possible - burst begins, revert s0 to s3 and go to s2
				s2Packets++ // the lost packet is the first packet lost in s2
				// the packet lost during the wrong transition from s0 to s3 was already counted to the s0 packets

				t03Packets-- // revert s0 to s3
				t02Packets++
				state = s2
				continue
			}
		} else { // packet received
			if state == s0 { // good reception during good state, stay in s0
				s0Packets++

				state = s0
				continue
			}
			if state == s1 { // good reception during good receptions in burst, decide whether to revert s1 and go to s0 or stay s1
				if numberOfPacketsReceivedDuringBurst < maxNumberOfPacketsReceivedDuringBurst { // stay in s1, burst goes on
					s1Packets++

					numberOfPacketsReceivedDuringBurst++

					state = s1
				} else { // revert whole s1 period and make the s2 to s0 transition
					s1Packets = s1Packets - (numberOfPacketsReceivedDuringBurst - 1) // except of the first packet all received packets during the good period weren't received in s1 but in s0
					// -1 because the first packet of the good ones was received in s2 and correctly counted, just the transition was the wrong one
					s0Packets = s0Packets + (numberOfPacketsReceivedDuringBurst - 1) // add all wrong counted packets correctly to s0

					numberOfPacketsReceivedDuringBurst = 0 // revert counter

					t21Packets-- // revert transition from s2 to s1
					t20Packets++ // make the transition from s2 to s0 afterwards
					state = s0
				}

				continue
			}
			if state == s2 { // good reception during burst loss, transition to s1
				s2Packets++

				numberOfPacketsReceivedDuringBurst++ // this is the first good packet during burst

				t21Packets++
				state = s1
				continue
			}
			if state == s3 { // good reception after loss in good state, transition to s0
				state = s0
				continue
			}

		}
	}

	// calculate the probabilities
	p02 = float64(t02Packets) / float64(s0Packets)
	p20 = float64(t20Packets) / float64(s2Packets)
	p12 = float64(t12Packets) / float64(s1Packets)
	p21 = float64(t21Packets) / float64(s2Packets)
	p03 = float64(t03Packets) / float64(s0Packets)

	// NaN indicates the division by 0, the state with this outgoing edge is never reached,
	// but the probability to leave it should be 1. If there is an error and the state get reached,
	// it is left with the next packet
	if math.IsNaN(p02) {
		p02 = 1
	}
	if math.IsNaN(p20) {
		p20 = 1
	}
	if math.IsNaN(p12) {
		p12 = 1
	}
	if math.IsNaN(p21) {
		p21 = 1
	}
	if math.IsNaN(p03) {
		p03 = 1
	}

	return
}
