package service

import (
	"cidr_checkr/internal/models"
	"net"
	"reflect"
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

	// Test case 1: Overlap between two CIDRs
	_, cidr1, _ := net.ParseCIDR("10.0.0.0/8")
	_, cidr2, _ := net.ParseCIDR("10.0.0.0/9")

	overlap := analyzer.checkOverlap(cidr1, cidr2)
	if overlap == nil {
		t.Fatalf("expected overlap; got none")
	}

	expectedOverlap := &models.CIDROverlap{
		CIDR1:        "10.0.0.0/8",
		CIDR2:        "10.0.0.0/9",
		OverlapRange: "10.0.0.0 - 10.127.255.255",
		OverlapHosts: 8388608,
	}

	if !reflect.DeepEqual(overlap, expectedOverlap) {
		t.Errorf("unexpected overlap: got %+v, want %+v", overlap, expectedOverlap)
	}

	// Test case 2: No overlap between two CIDRs
	_, cidr3, _ := net.ParseCIDR("192.168.1.0/24")
	_, cidr4, _ := net.ParseCIDR("192.168.2.0/24")

	overlap = analyzer.checkOverlap(cidr3, cidr4)
	if overlap != nil {
		t.Errorf("expected no overlap; got %+v", overlap)
	}
}

func TestInvalidCIDR(t *testing.T) {
	analyzer := NewAnalyzer()
	_, err := analyzer.Analyze([]string{"bro why are you sending a string"})

	if err == nil {
		t.Errorf("expected an error for invalid CIDR; got none")
	}
}

func TestAnalyzeWithOverlaps(t *testing.T) {
	analyzer := NewAnalyzer()

	// Test case: Multiple overlapping CIDRs
	cidrs := []string{"10.0.0.0/8", "10.0.0.0/9", "10.128.0.0/9"}
	response, err := analyzer.Analyze(cidrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(response.CIDRDetails) != 3 {
		t.Errorf("expected 3 CIDR details; got %d", len(response.CIDRDetails))
	}

	expectedOverlaps := []models.CIDROverlap{
		{
			CIDR1:        "10.0.0.0/8",
			CIDR2:        "10.0.0.0/9",
			OverlapRange: "10.0.0.0 - 10.127.255.255",
			OverlapHosts: 8388608,
		},
		{
			CIDR1:        "10.0.0.0/8",
			CIDR2:        "10.128.0.0/9",
			OverlapRange: "10.128.0.0 - 10.255.255.255",
			OverlapHosts: 8388608,
		},
	}

	if len(response.Overlaps) != len(expectedOverlaps) {
		t.Fatalf("expected %d overlaps; got %d", len(expectedOverlaps), len(response.Overlaps))
	}

	for i, overlap := range response.Overlaps {
		if !reflect.DeepEqual(overlap, expectedOverlaps[i]) {
			t.Errorf("unexpected overlap at index %d: got %+v, want %+v", i, overlap, expectedOverlaps[i])
		}
	}
}
