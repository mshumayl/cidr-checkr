package service

import (
	"bytes"
	"cidr_checkr/internal/models"
	"fmt"
	"net"
	"sort"
)

type Analyzer struct{}

func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) Analyze(cidrs []string) (*models.AnalysisResponse, error) {
	if len(cidrs) < 2 {
		return &models.AnalysisResponse{}, fmt.Errorf("at least two CIDRs are required")
	}
	response := &models.AnalysisResponse{
		CIDRDetails: make([]models.CIDRInfo, len(cidrs)),
		Overlaps:    []models.CIDROverlap{},
	}

	// Parse and sort CIDRs by starting IP
	parsedCIDRs := make([]*net.IPNet, len(cidrs))
	for i, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CIDR '%s': %w", cidr, err)
		}
		parsedCIDRs[i] = network

		// Add CIDR details
		response.CIDRDetails[i] = a.getCIDRInfo(cidr, network)
	}

	// Sort CIDRs by starting IP
	sort.Slice(parsedCIDRs, func(i, j int) bool {
		return bytes.Compare(parsedCIDRs[i].IP, parsedCIDRs[j].IP) < 0
	})

	// Check for overlaps in a single pass
	for i := 0; i < len(parsedCIDRs)-1; i++ {
		cidr1 := parsedCIDRs[i]
		cidr2 := parsedCIDRs[i+1]

		if overlap := a.checkOverlap(cidr1, cidr2); overlap != nil {
			response.Overlaps = append(response.Overlaps, *overlap)
			response.HasCollision = true
		}
	}

	return response, nil
}

func (a *Analyzer) getCIDRInfo(cidr string, network *net.IPNet) models.CIDRInfo {
	ones, bits := network.Mask.Size()
	hosts := 1 << (bits - ones)
	if bits == 32 {
		hosts -= 2 // Exclude network and broadcast addresses
	}

	// Calculate the last IP in the CIDR range
	lastIP := lastIP(network)

	return models.CIDRInfo{
		CIDR:       cidr,
		FirstIP:    network.IP.String(),
		LastIP:     lastIP.String(),
		TotalHosts: hosts,
	}
}

func (a *Analyzer) checkOverlap(cidr1, cidr2 *net.IPNet) *models.CIDROverlap {
	startIP, endIP := getOverlappingRange(cidr1, cidr2)
	if startIP == nil || endIP == nil {
		return nil
	}

	// Calculate the number of overlapping hosts
	overlapHosts := calculateIPRangeSize(startIP, endIP)

	return &models.CIDROverlap{
		CIDR1:        cidr1.String(),
		CIDR2:        cidr2.String(),
		OverlapRange: fmt.Sprintf("%s - %s", startIP.String(), endIP.String()),
		OverlapHosts: overlapHosts,
	}
}

func getOverlappingRange(cidr1, cidr2 *net.IPNet) (net.IP, net.IP) {
	// Find the maximum of the two starting IPs
	startIP := maxIP(cidr1.IP, cidr2.IP)

	// Find the minimum of the two ending IPs
	endIP := minIP(lastIP(cidr1), lastIP(cidr2))

	// If the start IP is greater than the end IP, there is no overlap
	if bytes.Compare(startIP, endIP) > 0 {
		return nil, nil
	}

	return startIP, endIP
}

// Helper function to calculate the last IP of a CIDR
func lastIP(network *net.IPNet) net.IP {
	ip := make(net.IP, len(network.IP))
	for i := range network.IP {
		ip[i] = network.IP[i] | ^network.Mask[i]
	}
	return ip
}

// Helper function to find the maximum of two IPs
func maxIP(ip1, ip2 net.IP) net.IP {
	if bytes.Compare(ip1, ip2) > 0 {
		return ip1
	}
	return ip2
}

// Helper function to find the minimum of two IPs
func minIP(ip1, ip2 net.IP) net.IP {
	if bytes.Compare(ip1, ip2) < 0 {
		return ip1
	}
	return ip2
}

func calculateIPRangeSize(startIP, endIP net.IP) int {
	start := ipToUint(startIP)
	end := ipToUint(endIP)
	if end < start {
		return 0
	}
	return int(end - start + 1)
}

// Helper function to convert an IP address to a uint64
func ipToUint(ip net.IP) uint64 {
	ip = ip.To4() // Ensure IPv4
	if ip == nil {
		return 0
	}
	return uint64(ip[0])<<24 | uint64(ip[1])<<16 | uint64(ip[2])<<8 | uint64(ip[3])
}
