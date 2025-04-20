package handlers

import (
	"bytes"
	"cidr_checkr/internal/models"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestAnalyzeCIDRs(t *testing.T) {
	// Prepare a valid request payload
	payload := models.CIDRRequest{
		CIDRs: []string{"192.168.1.0/24", "10.0.0.0/8"},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/analyze-cidrs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Call the handler
	AnalyzeCIDRs(w, req)

	// Check the response
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK; got %v", resp.Status)
	}

	var response models.AnalysisResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(response.CIDRDetails) != 2 {
		t.Errorf("expected 2 CIDR details; got %d", len(response.CIDRDetails))
	}

	expectedDetails := []models.CIDRInfo{
		{CIDR: "192.168.1.0/24", FirstIP: "192.168.1.0", LastIP: "192.168.1.255", TotalHosts: 254},
		{CIDR: "10.0.0.0/8", FirstIP: "10.0.0.0", LastIP: "10.255.255.255", TotalHosts: 16777214},
	}
	if !reflect.DeepEqual(response.CIDRDetails, expectedDetails) {
		t.Errorf("unexpected CIDR details: got %+v, want %+v", response.CIDRDetails, expectedDetails)
	}
}
