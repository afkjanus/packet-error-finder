package packetsAndErrors

import (
	"errors"
	"github.com/ajanusdev/packet-error-finder/loadingBar"
	"net"
	"sync"
)

// CalculateAllErrors is a public functions that provides the whole process of error calculation.
// From reading the packets from the files to calculating all errors.
//
// Takes:
//	leftPcapFiles 							[]string			- a slice which contains the path to the pcap files
//																  recorded on the left side
//	rightPcapFiles 							[]string			- a slice which contains the path to the pcap files
//																  recorded on the right side
//	macAddressesOnTheLeftSide 				[]net.HardwareAddr	- a slice containing the MAC addresses of the systems
// 																  which are connected on the left side
// 	macAddressesOnTheRight  				[]net.HardwareAddr 	- a slice containing the MAC addresses of the systems
//																  which are connected on the left side
//	ipAddressesOnTheLeft  					[]net.IP   			- a slice containing the IP addresses of the systems
//																  which are connected on the left side
//	ipAddressesOnTheRight  					[]net.IP   			- a slice containing the IP addresses of the systems
//																  which are connected on the left side
//	maxNumberOfPacketsReceivedDuringBurst 	int					- the number of packets, that can be received
//                    											  during a burst without changing into state 0
//
// Based on the provided addresses the network layer will be extracted.
// Layer 3 will be preferred.
// Addresses form just one side must be provided, at least one address in total.
//
// Returns: All values for the errors, an error if one occurred.
func CalculateAllErrors(
	leftPcapFiles []string,
	rightPcapFiles []string,
	macAddressesOnTheLeftSide []net.HardwareAddr,
	macAddressesOnTheRightSide []net.HardwareAddr,
	ipAddressesOnTheLeftSide []net.IP,
	ipAddressesOnTheRightSide []net.IP,
	maxNumberOfPacketsReceivedDuringBurst int,
) (
	leftToRightFlowMatchedPackets *MatchedPackets,
	rightToLeftFlowMatchedPackets *MatchedPackets,
	leftToRightLoss float64,
	rightToLeftLoss float64,
	leftToRightMarkovP02, leftToRightMarkovP20, leftToRightMarkovP21, leftToRightMarkovP12, leftToRightMarkovP03 float64,
	rightToLeftMarkovP02, rightToLeftMarkovP20, rightToLeftMarkovP21, rightToLeftMarkovP12, rightToLeftMarkovP03 float64,
	leftToRightDuplication float64,
	rightToLeftDuplication float64,
	leftToRightReorder float64,
	rightToLeftReorder float64,
	leftToRightJitter float64,
	rightToLeftJitter float64,
	err []error,
) {
	err = nil // no error is occurred until now

	packets, newPacketsErr := NewPackets(leftPcapFiles, rightPcapFiles) // extract the packets from the files
	if err = newPacketsErr; err != nil {
		return
	}

	// decide layer
	var layer int8 = 0
	macAddressesToInclude := append(macAddressesOnTheLeftSide, macAddressesOnTheRightSide...)
	if len(macAddressesToInclude) > 0 {
		layer = 2
	}
	ipAddressesToInclude := append(ipAddressesOnTheLeftSide, ipAddressesOnTheRightSide...)
	if len(ipAddressesToInclude) > 0 {
		layer = 3
	}
	// no addresses where given
	if layer == 0 {
		err = []error{errors.New("no MAC or IP Address given")}
		return
	}

	// filter for the MAC addresses
	if layer == 2 {
		packets.FilterPacketsBasedMacAddresses(macAddressesToInclude...)
	}

	// filter for the IP addresses
	if layer == 3 {
		packets.RemoveAllPacketsWithoutLayer3()
		packets.FilterPacketsBasedOnIpAddresses(ipAddressesToInclude...)
	}

	// split the packet arrays based on the flow direction of the packets
	leftToRightFlowPackets, rightToLeftFlowPackets, divideErr := packets.DividePacketsBasedOnDirection(
		macAddressesOnTheLeftSide,
		macAddressesOnTheRightSide,
		ipAddressesOnTheLeftSide,
		ipAddressesOnTheRightSide,
		layer,
	)
	if divideErr != nil {
		err = []error{divideErr}
		return
	}

	//
	// match the packets from the right and left side
	//
	leftToRightFlowMatchedPacketsChan := make(chan *MatchedPackets, 1)
	leftToRightNumberOfReorderedPacketsChan := make(chan int64, 1)
	rightToLeftFlowMatchedPacketsChan := make(chan *MatchedPackets, 1)
	rightToLeftNumberOfReorderedPacketsChan := make(chan int64, 1)

	// loading bar init
	bar := loadingBar.InitLoadingBar(
		2,
		len(leftToRightFlowPackets.LeftPackets()),
		len(rightToLeftFlowPackets.RightPackets()),
	)
	bar.RunLoadingBar()

	// channel to get errors from the goroutines
	errorChan := make(chan error, 2) // size 2 because 2 errors can occur at the same time

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()

		// create the MatchedPackets object to start matching
		leftToRightFlowMatchedPackets, errNewMatchedPackets := NewMatchedPackets(leftToRightFlowPackets, FlowLeftToRight)
		if errNewMatchedPackets != nil {
			errorChan <- errNewMatchedPackets
			return
		}

		// init the loading bar
		statusChan, err := bar.GetStatusChanWithCapacity(leftToRightFlowMatchedPackets.GetCapacityForStatusUpdateChan())
		if err != nil {
			errorChan <- err
			return
		}
		err = leftToRightFlowMatchedPackets.RegisterForStatusUpdate(statusChan)
		if err != nil {
			errorChan <- err
			return
		}
		// match the packets
		leftToRightNumberOfReorderedPackets, errMatchPackets := leftToRightFlowMatchedPackets.MatchPackets(layer, FlowLeftToRight)
		if errMatchPackets != nil {
			errorChan <- errMatchPackets
			return
		}

		// return
		leftToRightFlowMatchedPacketsChan <- leftToRightFlowMatchedPackets
		leftToRightNumberOfReorderedPacketsChan <- leftToRightNumberOfReorderedPackets
	}()
	go func() {
		defer wg.Done()

		// create the MatchedPackets object to start matching
		rightToLeftFlowMatchedPackets, errNewMatchedPackets := NewMatchedPackets(rightToLeftFlowPackets, FlowRightToLeft)
		if errNewMatchedPackets != nil {
			errorChan <- errNewMatchedPackets
			return
		}

		// init the loading bar
		statusChan, err := bar.GetStatusChanWithCapacity(rightToLeftFlowMatchedPackets.GetCapacityForStatusUpdateChan())
		if err != nil {
			errorChan <- err
			return
		}
		err = rightToLeftFlowMatchedPackets.RegisterForStatusUpdate(statusChan)
		if err != nil {
			errorChan <- err
			return
		}
		// match the packets
		rightToLeftNumberOfReorderedPackets, errMatchPackets := rightToLeftFlowMatchedPackets.MatchPackets(layer, FlowRightToLeft)
		if errMatchPackets != nil {
			errorChan <- errMatchPackets
			return
		}

		// return
		rightToLeftFlowMatchedPacketsChan <- rightToLeftFlowMatchedPackets
		rightToLeftNumberOfReorderedPacketsChan <- rightToLeftNumberOfReorderedPackets
	}()
	wg.Wait()

	// check if an error occurred
	select {
	case chanErr, errProvided := <-errorChan:
		if errProvided {
			err = []error{chanErr}
			return
		} else {
			// channel was closed, can't happen
		}
	default:
		// no error
	}

	// get the matched packets
	leftToRightFlowMatchedPackets = <-leftToRightFlowMatchedPacketsChan
	rightToLeftFlowMatchedPackets = <-rightToLeftFlowMatchedPacketsChan

	// deinit loading bar
	bar.StopLoadingBar()

	// calculate all errors
	leftToRightLoss = CalculateLossRate(leftToRightFlowMatchedPackets.MatchedPackets(), FlowLeftToRight)
	rightToLeftLoss = CalculateLossRate(rightToLeftFlowMatchedPackets.MatchedPackets(), FlowRightToLeft)
	leftToRightMarkovP02, leftToRightMarkovP20, leftToRightMarkovP21, leftToRightMarkovP12, leftToRightMarkovP03 = CalculateMarkovRates(
		leftToRightFlowMatchedPackets.MatchedPackets(),
		FlowLeftToRight,
		maxNumberOfPacketsReceivedDuringBurst,
	)
	rightToLeftMarkovP02, rightToLeftMarkovP20, rightToLeftMarkovP21, rightToLeftMarkovP12, rightToLeftMarkovP03 = CalculateMarkovRates(
		rightToLeftFlowMatchedPackets.MatchedPackets(),
		FlowRightToLeft,
		maxNumberOfPacketsReceivedDuringBurst,
	)
	leftToRightDuplication = CalculateDuplicateRate(leftToRightFlowMatchedPackets.MatchedPackets(), FlowLeftToRight)
	rightToLeftDuplication = CalculateDuplicateRate(rightToLeftFlowMatchedPackets.MatchedPackets(), FlowRightToLeft)
	leftToRightReorder = CalculateReorderRate(
		<-leftToRightNumberOfReorderedPacketsChan,
		leftToRightFlowMatchedPackets.MatchedPackets(),
	)
	rightToLeftReorder = CalculateReorderRate(
		<-rightToLeftNumberOfReorderedPacketsChan,
		rightToLeftFlowMatchedPackets.MatchedPackets(),
	)
	leftToRightJitter = CalculateJitter(leftToRightFlowMatchedPackets.MatchedPackets())
	rightToLeftJitter = CalculateJitter(rightToLeftFlowMatchedPackets.MatchedPackets())

	return
}
