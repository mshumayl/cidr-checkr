package service

import (
	"cidr_checkr/internal/models"
	"fmt"
	"net"
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

	parsedCIDRs := make([]*net.IPNet, len(cidrs))
	for i, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR format: %s", cidr)
		}
		parsedCIDRs[i] = network

		// Add CIDR details
		response.CIDRDetails[i] = a.getCIDRInfo(cidr, network)
	}

	// Check for overlaps
	for i := 0; i < len(parsedCIDRs); i++ {
		for j := i + 1; j < len(parsedCIDRs); j++ {
			if overlap := a.checkOverlap(parsedCIDRs[i], parsedCIDRs[j]); overlap != nil {
				response.Overlaps = append(response.Overlaps, *overlap)
				response.HasCollision = true
			}
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
	return models.CIDRInfo{
		CIDR:       cidr,
		FirstIP:    network.IP.String(),
		LastIP:     network.IP.Mask(network.Mask).String(),
		TotalHosts: hosts,
	}
}

func (a *Analyzer) checkOverlap(cidr1, cidr2 *net.IPNet) *models.CIDROverlap {
	if cidr1.Contains(cidr2.IP) || cidr2.Contains(cidr1.IP) {
		overlapNet := getOverlappingRange(cidr1, cidr2)
		ones, bits := overlapNet.Mask.Size()
		overlapHosts := 1 << uint(bits-ones)
		if bits == 32 {
			overlapHosts -= 2 // Exclude network and broadcast addresses
		}
		return &models.CIDROverlap{
			CIDR1:        cidr1.String(),
			CIDR2:        cidr2.String(),
			OverlapRange: fmt.Sprintf("%s - %s", cidr1.IP.String(), cidr2.IP.String()),
			OverlapHosts: 1,
		}
	}
	return nil
}

func getOverlappingRange(cidr1, cidr2 *net.IPNet) *net.IPNet {
	startIP := net.IPv4(0, 0, 0, 0)
	endIP := net.IPv4(255, 255, 255, 255)

	if cidr1.IP.Equal(startIP) || cidr2.IP.Equal(endIP) {
		return nil
	}

	return &net.IPNet{
		IP:   startIP,
		Mask: cidr1.Mask,
	}
}
