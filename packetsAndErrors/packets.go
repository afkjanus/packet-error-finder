package packetsAndErrors

import (
	"bytes"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"net"
	"sort"
	"sync"
)

// Packets includes 2 arrays of packets.
//
//	leftPackets  []gopacket.Packet	- holds the packets recorded on the left side
//	rightPackets []gopacket.Packet	- holds the packets recorded on the rightside
type Packets struct {
	leftPackets  []gopacket.Packet
	rightPackets []gopacket.Packet
}

// LeftPackets is a public getter function for the leftPackets field of a Packets structure.
func (packets *Packets) LeftPackets() []gopacket.Packet {
	return packets.leftPackets
}

// RightPackets is a public getter function for teh rightPackets field of a Packets structure.
func (packets *Packets) RightPackets() []gopacket.Packet {
	return packets.rightPackets
}

// NewPackets is a constructor for the Packets struct.
//
// Takes:
//	leftPcapFiles	[]string 	- a slice which contains the path to the pcap files recorded on the left side
//	rightPcapFiles	[]string	- a slice which contains the path to the pcap files recorded on the right side
//
// Returns:
//	*Packets	- a pointer to the constructed Packets struct.
//	[]error		- a slice of errors, if errors occurred during opening the files
func NewPackets(leftPcapFiles []string, rightPcapFiles []string) (*Packets, []error) {
	// the packet arrays will be returned using these channels
	leftPacketsChan := make(chan []gopacket.Packet)
	leftErrChan := make(chan error, len(leftPcapFiles))
	rightPacketChan := make(chan []gopacket.Packet)
	rightErrChan := make(chan error, len(leftPcapFiles))

	// extract the packets from the files
	go getPacketArrayFromPcapFile(leftPcapFiles, leftPacketsChan, leftErrChan)
	go getPacketArrayFromPcapFile(rightPcapFiles, rightPacketChan, rightErrChan)

	// check if an error occurred
	errs := make([]error, 0)
	for err := range leftErrChan {
		errs = append(errs, err)
	}
	for err := range rightErrChan {
		errs = append(errs, err)
	}
	if len(errs) != 0 { // return if an error occurred
		return nil, errs
	}

	// construct the Packets struct
	packets := Packets{
		leftPackets:  <-leftPacketsChan,
		rightPackets: <-rightPacketChan,
	}

	// return the pointer
	return &packets, nil
}

// getPacketArrayFromPcapFile is a private function to read one or more pcap files in and extract
// a slice of the type gopacket.Packet,
// which includes the packets of the file. The packets will be sorted by their timestamp.
//
// Takes:
//	pcapFiles	[]string				- a slice with the paths of one or more pcap files
//										  which packets should be extracted
//	packetChan chan []gopacket.Packet	- a channel to return the extracted packets
//	errChan chan error					- a channel to return errors which occurred during opening of files,
//										  will get closed if no error can occur anymore, gets just closed if
//										  no error occurred
func getPacketArrayFromPcapFile(pcapFiles []string, packetChan chan []gopacket.Packet, errChan chan error) {
	// the pcap files will provide packet sources, which are channels to the packets
	// create a channel for these packet sources first
	packetSourcesChan := make(chan *gopacket.PacketSource, len(pcapFiles))

	wg := sync.WaitGroup{}

	// open all pcap files in parallel and add the packet sources to the channel
	wg.Add(len(pcapFiles))
	for _, pcapFile := range pcapFiles {
		go func(pcapFile string) {
			defer wg.Done()
			if handle, err := pcap.OpenOffline(pcapFile); err == nil {
				packetSourcesChan <- gopacket.NewPacketSource(handle, handle.LinkType())
			} else {
				errChan <- err // the pcap file couldn't be opened
			}
		}(pcapFile)
	}

	// wait for all processing on the files to finish
	wg.Wait()
	close(packetSourcesChan)
	close(errChan) // no errors could happen anymore

	// extract the packets from the packet sources into a slice
	var packets []gopacket.Packet

	for packetSource := range packetSourcesChan {
		for packet := range packetSource.Packets() {
			packets = append(packets, packet)
		}
	}

	// sort the packets by the timestamp
	// use stable to keep elements with the same timestamp in the given order
	sort.SliceStable(packets, func(i, j int) bool {
		return packets[i].Metadata().Timestamp.Before(packets[j].Metadata().Timestamp)
	})

	// return the slice with the packets via the provided channel
	packetChan <- packets
}

// DividePacketsBasedOnDirection is a public function to split a Packets structure into 2,
// where each structure contains only the packets flowing either form left to right or from right to left
//
// Operates on:
//	packets	*Packets	- the Packets structure in which the packets should be split by flow direction
//
// Takes:
//	macAddressesOnTheLeft	[]net.HardwareAddr	- a slice containing the MAC addresses of the systems
//												  which are connected on the left side
//	macAddressesOnTheRight 	[]net.HardwareAddr	- a slice containing the MAC addresses of the systems
//												  which are connected on the left side
//	ipAddressesOnTheLeft 	[]net.IP			- a slice containing the IP addresses of the systems
//												  which are connected on the left side
//	ipAddressesOnTheRight 	[]net.IP			- a slice containing the IP addresses of the systems
//												  which are connected on the left side
//	layer					int8				- the ISO/OSI layer which should be used for the splitting,
//												  either 2 or 3
// Based on the used layer the slices of the other layer will not be used and can be empty.
// Addresses form just one side must be provided, at least one address in total.
//
// Returns:
//	leftToRightFlowPackets	*Packets	- a new Packets structure containing only the Packets flowing form left to right
//	rightToLeftFlowPackets	*Packets	- a new Packets structure containing only the Packets flowing from right to left
//	err						error		- the error if one occurs, nil if not
func (packets *Packets) DividePacketsBasedOnDirection(
	macAddressesOnTheLeft []net.HardwareAddr,
	macAddressesOnTheRight []net.HardwareAddr,
	ipAddressesOnTheLeft []net.IP,
	ipAddressesOnTheRight []net.IP,
	layer int8,
) (leftToRightFlowPackets, rightToLeftFlowPackets *Packets, err error) {
	leftToRightFlowLeftPacketsChan := make(chan []gopacket.Packet)
	leftToRightFlowRightPacketsChan := make(chan []gopacket.Packet)
	rightToLeftFlowLeftPacketsChan := make(chan []gopacket.Packet)
	rightToLeftFlowRightPacketsChan := make(chan []gopacket.Packet)
	errChanLeft := make(chan error)
	errChanRight := make(chan error)

	// split the 2 recorded sides parallel and independent
	go decideFlowDirection(
		packets.leftPackets,
		leftToRightFlowLeftPacketsChan,
		rightToLeftFlowLeftPacketsChan,
		errChanLeft,
		macAddressesOnTheLeft,
		macAddressesOnTheRight,
		ipAddressesOnTheLeft,
		ipAddressesOnTheRight,
		layer,
	)
	go decideFlowDirection(
		packets.rightPackets,
		leftToRightFlowRightPacketsChan,
		rightToLeftFlowRightPacketsChan,
		errChanRight,
		macAddressesOnTheLeft,
		macAddressesOnTheRight,
		ipAddressesOnTheLeft,
		ipAddressesOnTheRight,
		layer,
	)

	//check if an error appeared
	for err = range errChanLeft {
		return
	}
	for err = range errChanRight {
		return
	}

	// construct the new Packets structures
	leftToRightFlowPackets = &Packets{
		leftPackets:  <-leftToRightFlowLeftPacketsChan,
		rightPackets: <-leftToRightFlowRightPacketsChan,
	}

	rightToLeftFlowPackets = &Packets{
		leftPackets:  <-rightToLeftFlowLeftPacketsChan,
		rightPackets: <-rightToLeftFlowRightPacketsChan,
	}

	// return the new Packets structures
	return
}

// decideFlowDirection is a private function which calculates the flow direction of every packet in a slice of packets
//
// Takes:
//	packets						[]gopacket.Packet		- a slice containing packets which are flowing
//														  in both directions
//	leftToRightFlowPacketsChan	chan []gopacket.Packet	- a channel to return a slice of packets which are flowing
//														  from left to right
//	rightToLeftFlowPacketsChan	chan []gopacket.Packet	- a channel to return a slice of packets which are flowing
//														  from right to left
//	errChan 					chan error				- a channel to return errors,
//														  will get closed if no error can occur anymore,
//														  gets just closed if no error occurred
//	macAddressesOnTheLeft		[]net.HardwareAddr		- a slice containing the MAC addresses of the systems
//														  which are connected on the left side
//	macAddressesOnTheRight 		[]net.HardwareAddr		- a slice containing the MAC addresses of the systems
//					 									  which are connected on the left side
//	ipAddressesOnTheLeft 		[]net.IP				- a slice containing the IP addresses of the systems
//														  which are connected on the left side
//	ipAddressesOnTheRight 		[]net.IP				- a slice containing the IP addresses of the systems
//														  which are connected on the left side
//	layer						int8					- the ISO/OSI layer which should be used for the splitting,
//														  either 2 or 3
// Based on the used layer the slices of the other layer will not be used and can be empty.
// Addresses form just one side must be provided, at least one address in total.
func decideFlowDirection(
	packets []gopacket.Packet,
	leftToRightFlowPacketsChan chan []gopacket.Packet,
	rightToLeftFlowPacketsChan chan []gopacket.Packet,
	errChan chan error,
	macAddressesOnTheLeft []net.HardwareAddr,
	macAddressesOnTheRight []net.HardwareAddr,
	ipAddressesOnTheLeft []net.IP,
	ipAddressesOnTheRight []net.IP,
	layer int8,
) {
	// create the slices for the packets of each flow direction
	leftToRightFlowPackets := make([]gopacket.Packet, 0)
	rightToLeftFlowPackets := make([]gopacket.Packet, 0)

	// create string slices containing the addresses of the used layer as strings

	// evaluate the needed length of the slice
	numberOfLeftAddresses := 0
	numberOfRightAddresses := 0
	if layer == LinkLayer {
		numberOfLeftAddresses = len(macAddressesOnTheLeft)
		numberOfRightAddresses = len(macAddressesOnTheRight)
	} else {
		numberOfLeftAddresses = len(ipAddressesOnTheLeft)
		numberOfRightAddresses = len(ipAddressesOnTheRight)
	}

	addressesOnTheLeftStrings := make([]string, 0, numberOfLeftAddresses)
	addressesOnTheRightStrings := make([]string, 0, numberOfRightAddresses)

	// get the addresses as strings and append them to the slices
	if layer == LinkLayer {
		for _, macAddress := range macAddressesOnTheLeft {
			addressesOnTheLeftStrings = append(addressesOnTheLeftStrings, macAddress.String())
		}
		for _, macAddress := range macAddressesOnTheRight {
			addressesOnTheRightStrings = append(addressesOnTheRightStrings, macAddress.String())
		}
	} else {
		for _, ipAddress := range ipAddressesOnTheLeft {
			addressesOnTheLeftStrings = append(addressesOnTheLeftStrings, ipAddress.String())
		}
		for _, ipAddress := range ipAddressesOnTheRight {
			addressesOnTheRightStrings = append(addressesOnTheRightStrings, ipAddress.String())
		}
	}

	// decide the flow direction for each packet
	for _, packet := range packets {
		var src string
		var dst string

		// get the source and destination addresses of the packet
		if layer == LinkLayer {
			src = packet.LinkLayer().LinkFlow().Src().String()
			dst = packet.LinkLayer().LinkFlow().Dst().String()
		} else {
			src = packet.NetworkLayer().NetworkFlow().Src().String()
			dst = packet.NetworkLayer().NetworkFlow().Dst().String()
		}

		if len(addressesOnTheLeftStrings) > 0 {
			if stringSliceContains(addressesOnTheLeftStrings, src) {
				// if the packet has an address of the left side as source address it flows from left to right
				leftToRightFlowPackets = append(leftToRightFlowPackets, packet)
				continue
			}

			if stringSliceContains(addressesOnTheLeftStrings, dst) {
				// if the packet has an address of the left side as destination address it flows from left to right
				rightToLeftFlowPackets = append(rightToLeftFlowPackets, packet)
				continue
			}
		}

		if len(addressesOnTheRightStrings) > 0 {
			if stringSliceContains(addressesOnTheRightStrings, src) {
				// if the packet has an address of the right side as source address it flows from right to left
				rightToLeftFlowPackets = append(rightToLeftFlowPackets, packet)
				continue
			}

			if stringSliceContains(addressesOnTheRightStrings, dst) {
				// if the packet has an address of the right side as destination address it flows from right to left
				leftToRightFlowPackets = append(leftToRightFlowPackets, packet)
				continue
			}
		}

		// can't decide on flow direction
		// report error and return
		errChan <- errors.New("there aren't any addresses given or there is a packet containing none of the given addresses so flow direction can't be determined. Use FilterPacketsBasedOnIpAddresses or FilterPacketsBasedOnMacAddresses to filter the packets first")
		close(errChan)
		return
	}
	close(errChan) // no errors can occur anymore

	// return the arrays using the channels
	leftToRightFlowPacketsChan <- leftToRightFlowPackets
	rightToLeftFlowPacketsChan <- rightToLeftFlowPackets
}

// FilterPacketsBasedOnIpAddresses is a public function to filter the slices in a Packets structure
// by given IP addresses
//
// Operates on:
//	packets *Packets	- the Packets structure with the packet slices that should be filtered,
//						  the packet slices will be manipulated
//
// Takes:
//	ipAddresses ...net.IP	- one or multiple IP addresses that should be included as source
//							  or destination in the packets
func (packets *Packets) FilterPacketsBasedOnIpAddresses(ipAddresses ...net.IP) {
	// get the IP Addresses as a strings slice
	ipAddressesStrings := make([]string, 0, len(ipAddresses))
	for _, ipAddress := range ipAddresses {
		ipAddressesStrings = append(ipAddressesStrings, ipAddress.String())
	}

	// create channels for the indexes of the packet which should be removed
	leftPacketsToRemoveIndexChan := make(chan int)
	leftWg := sync.WaitGroup{}
	rightPacketsToRemoveIndexChan := make(chan int)
	rightWg := sync.WaitGroup{}

	// check if the packet must be removed in parallel for the left packets
	leftWg.Add(len(packets.leftPackets))
	for packetIndex, packet := range packets.leftPackets {
		go func(packetIndex int, packet gopacket.Packet) {
			defer leftWg.Done()
			if checkIfPacketIsToRemoveBasedOnIpAddresses(packet, ipAddressesStrings...) { // check
				leftPacketsToRemoveIndexChan <- packetIndex
			}
		}(packetIndex, packet)
	}

	// check if the packet must be removed in parallel for the right packets
	rightWg.Add(len(packets.rightPackets))
	for packetIndex, packet := range packets.rightPackets {
		go func(packetIndex int, packet gopacket.Packet) {
			defer rightWg.Done()
			if checkIfPacketIsToRemoveBasedOnIpAddresses(packet, ipAddressesStrings...) { // check
				rightPacketsToRemoveIndexChan <- packetIndex
			}
		}(packetIndex, packet)
	}

	// wait for the checks to finish
	go func() {
		leftWg.Wait()
		close(leftPacketsToRemoveIndexChan)
	}()

	go func() {
		rightWg.Wait()
		close(rightPacketsToRemoveIndexChan)
	}()

	// remove the packets to remove from the slices
	removeWg := sync.WaitGroup{}

	removeWg.Add(1)
	go func() {
		defer removeWg.Done()
		removePacketsFromSliceBasedOnIndexesChan(leftPacketsToRemoveIndexChan, &packets.leftPackets)
	}()

	removeWg.Add(1)
	go func() {
		defer removeWg.Done()
		removePacketsFromSliceBasedOnIndexesChan(rightPacketsToRemoveIndexChan, &packets.rightPackets)
	}()

	// sync before returning
	removeWg.Wait()
}

// FilterPacketsBasedMacAddresses is a public function to filter the slices in a Packets structure
// by given MAC addresses
//
// Operates on:
//	packets *Packets	- the Packets structure with the packet slices that should be filtered,
//						  the packet slices will be manipulated
//
// Takes:
//	ipAddresses ...net.HardwareAddr	- one or multiple MAC addresses that should be included as source
//									  or destination in the packets
func (packets *Packets) FilterPacketsBasedMacAddresses(macAddresses ...net.HardwareAddr) {
	// get the MAC Addresses as a strings slice
	macAddressStrings := make([]string, 0, len(macAddresses))
	for _, macAddress := range macAddresses {
		macAddressStrings = append(macAddressStrings, macAddress.String())
	}

	// create channels for the indexes of the packet which should be removed
	leftPacketsToRemoveIndexChan := make(chan int)
	leftWg := sync.WaitGroup{}
	rightPacketsToRemoveIndexChan := make(chan int)
	rightWg := sync.WaitGroup{}

	// check if the packet must be removed in parallel for the left packets
	leftWg.Add(len(packets.leftPackets))
	for packetIndex, packet := range packets.leftPackets {
		go func(packetIndex int, packet gopacket.Packet) {
			defer leftWg.Done()
			if checkIfPacketIsToRemoveBasedOnMacAddresses(packet, macAddressStrings...) {
				leftPacketsToRemoveIndexChan <- packetIndex
			}
		}(packetIndex, packet)
	}

	// check if the packet must be removed in parallel for the right packets
	rightWg.Add(len(packets.rightPackets))
	for packetIndex, packet := range packets.rightPackets {
		go func(packetIndex int, packet gopacket.Packet) {
			defer rightWg.Done()
			if checkIfPacketIsToRemoveBasedOnMacAddresses(packet, macAddressStrings...) {
				rightPacketsToRemoveIndexChan <- packetIndex
			}
		}(packetIndex, packet)
	}

	// wait for the checks to finish
	go func() {
		leftWg.Wait()
		close(leftPacketsToRemoveIndexChan)
	}()

	go func() {
		rightWg.Wait()
		close(rightPacketsToRemoveIndexChan)
	}()

	// remove the packets to remove from the slices
	removeWg := sync.WaitGroup{}

	removeWg.Add(1)
	go func() {
		defer removeWg.Done()
		removePacketsFromSliceBasedOnIndexesChan(leftPacketsToRemoveIndexChan, &packets.leftPackets)
	}()

	removeWg.Add(1)
	go func() {
		defer removeWg.Done()
		removePacketsFromSliceBasedOnIndexesChan(rightPacketsToRemoveIndexChan, &packets.rightPackets)
	}()

	// sync before returning
	removeWg.Wait()
}

// RemoveAllPacketsWithoutLayer3 is a public function to remove all packets in a Packets struct
// which do not include a layer 3 datagram.
//
// Operates on:
//	packets *Packets	- the Packets structure with the packet slices that should be filtered,
//						  the packet slices will be manipulated
func (packets *Packets) RemoveAllPacketsWithoutLayer3() {
	// create channels for the indexes of the packets to remove
	leftPacketsToRemovePositionsChan := make(chan int)
	leftWg := sync.WaitGroup{}
	rightPacketsToRemovePositionsChan := make(chan int)
	rightWg := sync.WaitGroup{}

	// check if the packet must be removed in parallel for the left packets
	leftWg.Add(len(packets.leftPackets))
	for packetPosition, packet := range packets.leftPackets {
		go func(packetPosition int, packet gopacket.Packet) {
			defer leftWg.Done()
			if packet.NetworkLayer() == nil { // remove the packet if there is no layer 3
				leftPacketsToRemovePositionsChan <- packetPosition
			}
		}(packetPosition, packet)
	}

	// check if the packet must be removed in parallel for the right packets
	rightWg.Add(len(packets.rightPackets))
	for packetPosition, packet := range packets.rightPackets {
		go func(packetPosition int, packet gopacket.Packet) {
			defer rightWg.Done()
			if packet.NetworkLayer() == nil { // remove the packet if there is no layer 3
				rightPacketsToRemovePositionsChan <- packetPosition
			}
		}(packetPosition, packet)
	}

	// wait for the checks to finish
	go func() {
		leftWg.Wait()
		close(leftPacketsToRemovePositionsChan)
	}()

	go func() {
		rightWg.Wait()
		close(rightPacketsToRemovePositionsChan)
	}()

	// remove the packets to remove from the slices
	removeWg := sync.WaitGroup{}

	removeWg.Add(1)
	go func() {
		defer removeWg.Done()
		removePacketsFromSliceBasedOnIndexesChan(leftPacketsToRemovePositionsChan, &packets.leftPackets)
	}()

	removeWg.Add(1)
	go func() {
		defer removeWg.Done()
		removePacketsFromSliceBasedOnIndexesChan(rightPacketsToRemovePositionsChan, &packets.rightPackets)
	}()

	// sync before returning
	removeWg.Wait()
}

// checkIfPacketIsToRemoveBasedOnMacAddresses is a private function checks weather a packet includes given
// MAC addresses as source or destination or not. Packets are to remove if a packet includes none of them.
//
// Takes:
//	packet 			gopacket.Packet	- the packet which should be checked if it is to remove
//	macAddresses 	...string		- one or more MAC addresses of
//									  which at least one should be included as source or destination
//
// Returns:
//	bool	- true if the packet doesn't include one of the given addresses and is to remove,
//			  false if it does include one and no removal is needed
func checkIfPacketIsToRemoveBasedOnMacAddresses(packet gopacket.Packet, macAddresses ...string) bool {
	// get the MAC addresses of the packet
	leftMacAddress, rightMacAddress := packet.LinkLayer().LinkFlow().Endpoints()

	// convert the addresses to strings
	leftMacAddressString := leftMacAddress.String()
	rightMacAddressString := rightMacAddress.String()

	// check for each provided MAC address if it is identical to the source or destination address
	for _, macAddress := range macAddresses {
		if leftMacAddressString == macAddress || rightMacAddressString == macAddress {
			return false // in case of a match, return false
		}
	}

	// none of the provided addresses are included are either the source or destination address
	return true
}

// checkIfPacketIsToRemoveBasedOnIpAddresses is a private function checks weather a packet includes given
// IP addresses as source or destination or not. Packets are to remove if a packet includes none of them.
//
// Takes:
//	packet 			gopacket.Packet	- the packet which should be checked if it is to remove
//	ipAddresses 	...string		- one or more IP addresses of
//									  which at least one should be included as source or destination
//
// Returns:
//	bool	- true if the packet doesn't include one of the given addresses and is to remove,
//			  false if it does include one and no removal is needed
func checkIfPacketIsToRemoveBasedOnIpAddresses(packet gopacket.Packet, ipAddresses ...string) bool {
	// get the IP addresses of the packet
	leftIpAddress, rightIpAddress := packet.NetworkLayer().NetworkFlow().Endpoints()

	// convert the addresses to strings
	leftIpAddressString := leftIpAddress.String()
	rightIpAddressString := rightIpAddress.String()

	// check for each provided IP address if it is identical to the source or destination address
	for _, ipAddress := range ipAddresses {
		if leftIpAddressString == ipAddress || rightIpAddressString == ipAddress {
			return false // in case of a match, return false
		}
	}

	// none of the provided addresses are included are either the source or destination address
	return true
}

// removePacketsFromSliceBasedOnIndexesChan is a private function which removes the packets
// at a given indexes in a slice of packets.
// The removing of the packets will be returned as a side effect.
//
// Takes:
//	packetsToRemoveIndexesChan 	chan int			- a channel containing all the indexes of the packets
//													  which should be removed
//	packets 					*[]gopacket.Packet	- the pointer to the slice of packets
//													  where the packets should be removed
func removePacketsFromSliceBasedOnIndexesChan(packetsToRemoveIndexesChan chan int, packets *[]gopacket.Packet) {
	// get the indexes of the packets to remove into a slice
	packetIndexesToRemove := make([]int, 0)
	for packetToRemove := range packetsToRemoveIndexesChan {
		packetIndexesToRemove = append(packetIndexesToRemove, packetToRemove)
	}

	// sort the slice of indexes
	sort.Ints(packetIndexesToRemove)
	// reverse the slice of indexes, so removing of the packets in order of the slice won't affect the indexes
	// of the other packets in the slice
	reverseSlice(packetIndexesToRemove)

	// remove the packets one by one
	for _, rightPacketToRemove := range packetIndexesToRemove {
		removeObjectFromSliceAtIndex(rightPacketToRemove, packets)
	}
}

// equalPacket is a private function which checks if two packets are equal on a specified layer
//
// Takes:
//	leftPacket 	gopacket.Packet	- one of the packets which are checked for equality
//	rightPacket	gopacket.Packet	- one of the packets which are checked for equality
//	layer 		int8			- the ISO/OSI layer on which the packets are checked for equality, either layer 2 or 3
//
// Returns:
//	bool	- true of packets are equal, false if not
func equalPacket(leftPacket gopacket.Packet, rightPacket gopacket.Packet, layer int8) bool {
	if layer == LinkLayer {
		return equalLayer2Packet(leftPacket, rightPacket)
	}
	if layer == NetworkLayer {
		return equalLayer3Packet(leftPacket, rightPacket)
	}

	return false
}

// equalLayer2Packet is private function to check to packets on layer 2 for equality.
// Two packets are equal if the source and destination MAC addresses are equal and if the payloads are equal.
//
// Takes:
//	leftPacket 	gopacket.Packet	- one of the packets which are checked for equality
//	rightPacket	gopacket.Packet	- one of the packets which are checked for equality
//
// Returns:
//	bool	- true of packets are equal, false if not
func equalLayer2Packet(leftPacket gopacket.Packet, rightPacket gopacket.Packet) bool {
	// check if the MAC addresses are equal before comparing the payload to safe computing time
	if leftPacket.LinkLayer().LinkFlow().Src() == rightPacket.LinkLayer().LinkFlow().Src() &&
		leftPacket.LinkLayer().LinkFlow().Dst() == rightPacket.LinkLayer().LinkFlow().Dst() {

		// compare the payload
		if bytes.Equal(leftPacket.LinkLayer().LayerPayload(), rightPacket.LinkLayer().LayerPayload()) {
			return true
		}
	}

	return false
}

// equalLayer3Packet is a private function to check to packets on layer 3 for equality.
// Two packets are equal if the source and destination IP addresses are equal and if the payloads are equal.
// Takes:
//	leftPacket 	gopacket.Packet	- one of the packets which are checked for equality
//	rightPacket	gopacket.Packet	- one of the packets which are checked for equality
//
// Returns:
//	bool	- true of packets are equal, false if not
func equalLayer3Packet(leftPacket gopacket.Packet, rightPacket gopacket.Packet) bool {
	// check if the IP addresses are equal before comparing the payload to safe computing time
	if leftPacket.NetworkLayer().NetworkFlow().Src() == rightPacket.NetworkLayer().NetworkFlow().Src() &&
		leftPacket.NetworkLayer().NetworkFlow().Dst() == rightPacket.NetworkLayer().NetworkFlow().Dst() {

		// compare the payload
		if bytes.Equal(leftPacket.NetworkLayer().LayerPayload(), rightPacket.NetworkLayer().LayerPayload()) {
			return true
		}
	}

	return false
}
