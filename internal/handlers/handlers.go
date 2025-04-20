package handlers

import (
	"cidr_checkr/internal/models"
	"cidr_checkr/internal/service"
	"encoding/json"
	"fmt"
	"net/http"
)

func AnalyzeCIDRs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.CIDRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if len(req.CIDRs) < 2 {
		http.Error(w, "At least two CIDRs are required", http.StatusBadRequest)
		return
	}

	analyzer := service.NewAnalyzer()
	response, err := analyzer.Analyze(req.CIDRs)
	if err != nil {
		http.Error(w, "Error analyzing CIDRs: %v", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Error analyzing CIDRs: %v", err), http.StatusInternalServerError)
		return
	}
}
