package models

type CIDRRequest struct {
	CIDRs []string `json:"cidrs"`
}

type CIDROverlap struct {
	CIDR1        string `json:"cidr1"`
	CIDR2        string `json:"cidr2"`
	OverlapRange string `json:"overlap_range"`
	OverlapHosts int    `json:"overlap_hosts"`
}

type CIDRInfo struct {
	CIDR       string `json:"cidr"`
	FirstIP    string `json:"first_ip"`
	LastIP     string `json:"last_ip"`
	TotalHosts int    `json:"total_hosts"`
}

type AnalysisResponse struct {
	CIDRDetails  []CIDRInfo    `json:"cidr_details"`
	Overlaps     []CIDROverlap `json:"overlaps"`
	HasCollision bool          `json:"has_collision"`
}
