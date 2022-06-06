package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/ajanusdev/packet-error-finder/packetsAndErrors"
	"net"
	"strings"
)

func main() {
	// provide command line options
	leftPcapFilesFlag := flag.String("leftPcapFile", "", "Defines the full path to the left pacp files.\nMultiple files are divided by |.\nMandatory")
	rightPcapFilesFlag := flag.String("rightPcapFile", "", "Defines the full path to the right pacp files.\nMultiple files are divided by |.\nMandatory")

	macAddressesOnTheLeftSideFlag := flag.String("MACLeft", "", "Defines the MAC addresses on the left side of the recorded line.\nMultiple addresses are divided by |.\nAt least one MAC address or IP address must be provided in total.")
	macAddressesOnTheRightSideFlag := flag.String("MACRight", "", "Defines the MAC addresses on the right side of the recorded line.\nMultiple addresses are divided by |.\nAt least one MAC address or IP address must be provided in total.")

	ipAddressesOnTheLeftSideFlag := flag.String("IPLeft", "", "Defines the IP addresses on the left side of the recorded line.\nMultiple addresses are divided by |.\nAt least one MAC address or IP address must be provided in total.")
	ipAddressesOnTheRightSideFlag := flag.String("IPRight", "", "Defines the IP addresses on the right side of the recorded line.\nMultiple addresses are divided by |.\nAt least one MAC address or IP address must be provided in total.")

	maxNumberOfPacketsReceivedDuringBurst := flag.Int("burst", 16, "Defines the number of packets, that can be received\nduring a burst without changing into state 0.")

	licenses := flag.Bool("showUsedLicenses", false, "Show the used FOSS licenses.")

	flag.Parse()

	// handle licenses flg
	if *licenses {
		showLicenses()
		return
	}

	// extract the pcap file names
	leftPcapFiles := strings.Split(*leftPcapFilesFlag, "|")
	rightPcapFiles := strings.Split(*rightPcapFilesFlag, "|")

	// extract all addresses
	macAddressesOnTheLeftSideStrings := strings.Split(*macAddressesOnTheLeftSideFlag, "|")
	macAddressesOnTheLeftSide := make([]net.HardwareAddr, 0, len(macAddressesOnTheLeftSideStrings))
	if *macAddressesOnTheLeftSideFlag != "" {
		if len(macAddressesOnTheLeftSideStrings) > 0 {
			for _, macAddressOnTheLeftSideString := range macAddressesOnTheLeftSideStrings {
				macAddressOnTheLeftSide, err := net.ParseMAC(macAddressOnTheLeftSideString)
				if err != nil {
					fmt.Println(macAddressOnTheLeftSideString)
					panic(err)
				}

				macAddressesOnTheLeftSide = append(macAddressesOnTheLeftSide, macAddressOnTheLeftSide)
			}
		}
	}

	macAddressesOnTheRightSideStrings := strings.Split(*macAddressesOnTheRightSideFlag, "|")
	macAddressesOnTheRightSide := make([]net.HardwareAddr, 0, len(macAddressesOnTheRightSideStrings))
	if *macAddressesOnTheRightSideFlag != "" {
		if len(macAddressesOnTheRightSideStrings) > 0 {
			for _, macAddressOnTheRightSideString := range macAddressesOnTheRightSideStrings {
				macAddressOnTheRightSide, err := net.ParseMAC(macAddressOnTheRightSideString)
				if err != nil {
					fmt.Println(macAddressOnTheRightSideString)
					panic(err)
				}

				macAddressesOnTheRightSide = append(macAddressesOnTheRightSide, macAddressOnTheRightSide)
			}
		}
	}

	ipAddressesOnTheLeftSideStrings := strings.Split(*ipAddressesOnTheLeftSideFlag, "|")
	ipAddressesOnTheLeftSide := make([]net.IP, 0, len(ipAddressesOnTheLeftSideStrings))
	if *ipAddressesOnTheLeftSideFlag != "" {
		if len(ipAddressesOnTheLeftSideStrings) > 0 {
			for _, ipAddressOnTheLeftSideString := range ipAddressesOnTheLeftSideStrings {
				ipAddressOnTheLeftSide := net.ParseIP(ipAddressOnTheLeftSideString)
				if ipAddressOnTheLeftSide == nil {
					fmt.Println(ipAddressOnTheLeftSideString)
					err := errors.New("no valid IP Address")
					panic(err)
				}

				ipAddressesOnTheLeftSide = append(ipAddressesOnTheLeftSide, ipAddressOnTheLeftSide)
			}
		}
	}

	ipAddressesOnTheRightSideStrings := strings.Split(*ipAddressesOnTheRightSideFlag, "|")
	ipAddressesOnTheRightSide := make([]net.IP, 0, len(ipAddressesOnTheRightSideStrings))
	if *ipAddressesOnTheRightSideFlag != "" {
		if len(ipAddressesOnTheRightSideStrings) > 0 {
			for _, ipAddressOnTheRightSideString := range ipAddressesOnTheRightSideStrings {
				ipAddressOnTheRightSide := net.ParseIP(ipAddressOnTheRightSideString)
				if ipAddressOnTheRightSide == nil {
					fmt.Println(ipAddressOnTheRightSideString)
					err := errors.New("no valid IP Address")
					panic(err)
				}

				ipAddressesOnTheRightSide = append(ipAddressesOnTheRightSide, ipAddressOnTheRightSide)
			}
		}
	}

	// calculate the errors
	leftToRightFlowMatchedPackets, rightToLeftFlowMatchedPackets, leftToRightLoss, rightToLeftLoss, leftToRightMarkovP02, leftToRightMarkovP20, leftToRightMarkovP21, leftToRightMarkovP12, leftToRightMarkovP03, rightToLeftMarkovP02, rightToLeftMarkovP20, rightToLeftMarkovP21, rightToLeftMarkovP12, rightToLeftMarkovP03, leftToRightDuplication, rightToLeftDuplication, leftToRightReorder, rightToLeftReorder, leftToRightJitter, rightToLeftJitter, err := packetsAndErrors.CalculateAllErrors(
		leftPcapFiles,
		rightPcapFiles,
		macAddressesOnTheLeftSide,
		macAddressesOnTheRightSide,
		ipAddressesOnTheLeftSide,
		ipAddressesOnTheRightSide,
		*maxNumberOfPacketsReceivedDuringBurst,
	)

	// check for error during error finding
	if err != nil {
		for _, e := range err {
			fmt.Println(e)
		}
		panic(errors.New("please resolve the occurred errors"))
	}

	// Print results
	fmt.Println("Packets that are flowing from left to right: ", len(leftToRightFlowMatchedPackets.MatchedPackets()))
	fmt.Println("Packets that are flowing from right to left: ", len(rightToLeftFlowMatchedPackets.MatchedPackets()))

	fmt.Println("Left to right jitter: ", leftToRightJitter, " ms")
	fmt.Println("Right to left jitter: ", rightToLeftJitter, " ms")
	fmt.Println("Left to right loss rate: ", leftToRightLoss)
	fmt.Println("Right to left loss rate: ", rightToLeftLoss)
	fmt.Println("Left to right duplicate rate: ", leftToRightDuplication)
	fmt.Println("Right to left duplicate rate: ", rightToLeftDuplication)
	fmt.Println("Left to right reorder rate: ", leftToRightReorder)
	fmt.Println("Right to left reorder rate: ", rightToLeftReorder)
	fmt.Println("Markov probabilities for packets flowing from left to right:")
	fmt.Println(
		"\tP02: ", leftToRightMarkovP02, "\n",
		"\tP20: ", leftToRightMarkovP20, "\n",
		"\tP21: ", leftToRightMarkovP21, "\n",
		"\tP12: ", leftToRightMarkovP12, "\n",
		"\tP03: ", leftToRightMarkovP03,
	)
	fmt.Println("Markov probabilities for packets flowing from right to left:")
	fmt.Println(
		"\tP02: ", rightToLeftMarkovP02, "\n",
		"\tP20: ", rightToLeftMarkovP20, "\n",
		"\tP21: ", rightToLeftMarkovP21, "\n",
		"\tP12: ", rightToLeftMarkovP12, "\n",
		"\tP03: ", rightToLeftMarkovP03,
	)
}
