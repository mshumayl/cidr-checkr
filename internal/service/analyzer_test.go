package service

import (
	"cidr_checkr/internal/models"
	"net"
	"testing"
)

func TestAnalyze(t *testing.T) {
	analyzer := NewAnalyzer()

	// Test with valid CIDRs
	cidrs := []string{"192.168.1.0/24", "10.0.0.0/8"}
	response, err := analyzer.Analyze(cidrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(response.CIDRDetails) != 2 {
		t.Errorf("expected 2 CIDR details; got %d", len(response.CIDRDetails))
	}

	// Test with invalid CIDRs
	cidrs = []string{"invalid-cidr"}
	_, err = analyzer.Analyze(cidrs)
	if err == nil {
		t.Errorf("expected an error for invalid CIDR; got none")
	}
}

func TestGetCIDRInfo(t *testing.T) {
	analyzer := NewAnalyzer()
	_, network, _ := net.ParseCIDR("192.168.1.0/24")

	info := analyzer.getCIDRInfo("192.168.1.0/24", network)
	if info.TotalHosts != 254 {
		t.Errorf("expected 254 hosts; got %d", info.TotalHosts)
	}
}

func TestCheckOverlap(t *testing.T) {
	analyzer := NewAnalyzer()
	_, cidr1, _ := net.ParseCIDR("192.168.1.0/24")
	_, cidr2, _ := net.ParseCIDR("192.168.1.128/25")

	overlap := analyzer.checkOverlap(cidr1, cidr2)
	if overlap == nil {
		t.Errorf("expected overlap; got none")
	}
}
