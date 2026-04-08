package scanner

import icmptransport "github.com/ostefani/subnetlens/transports/icmp"

type ICMPScanner = icmptransport.Scanner

func NewICMPScanner() (*ICMPScanner, error) {
	return icmptransport.NewScanner()
}
