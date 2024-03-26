# Packet Error Finder
Packet Error Finder is an open source tool to find errors occuring in a network.

The goal of Packet Error Finder is to give the user the ability to find errors and recreating them using the Linux tool netem.
To find errors two tcpdump files containing recorded packets are needed, those files are compared to find errors.
This software can find the following errors:
- Loss, including loss as a burst error
- Duplication
- Reordering
- Jitter

The results are presented in a way which can be used directly for error recreation in netem.
Therefore, Packet Error Finder can be used to analyze real world network environments and recreate the detected errors to harden network protocols against them.
To analyze and recreate packets this work is best paired with SEDER, from the work [*Cost-Effective Network Packet Manipulation and Error-Detection Device* (https://doi.org/10.1109/CCNC51664.2024.10454761)](https://doi.org/10.1109/CCNC51664.2024.10454761), presented at the 21st Consumer Communications & Networking Conference (CCNC).

## Usage
- Clone the repository
- Build the software using `go build`
- Run it using `./packet-error-finder`
All supported flags are provided using `./packet-error-finder -h`. At least the flags `-leftPcapFile` and `-rightPcapFile` must be used to specify the packet recordings to compare.

## Contribution
We are very happy about your contribution to this work.
- Just fork the repository
- Create your feature branch
- Commit your changes
- Push your changes
- Create a pull request

## Credits
Packet Error Finder uses:
- [google/gopacket](https://github.com/google/gopacket)
- [cespare/xxhash](https://github.com/google/gopacket)
- [golang.org/x/sync](https://pkg.go.dev/golang.org/x/sync)
- [golang.org/x/term](https://pkg.go.dev/golang.org/x/term)
- [golang.org/x/net](https://pkg.go.dev/golang.org/x/net)
- [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys)

## License
Packet Error Finder is distributed under the [MIT License](https://github.com/afkjanus/packet-error-finder/blob/main/LICENSE.md).
