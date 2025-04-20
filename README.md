# cidr-checkr

cidr-checkr is a tool for quickly analyzing CIDR ranges, detecting overlaps, and providing detailed insights into IP address allocations. It is designed for network engineers, security teams, and DevOps professionals to validate and manage IP address configurations effectively.

This tool is currently implemented as a headless HTTP API server, making it easy to integrate into other systems or automation workflows.

## Features

- **CIDR Analysis**: Provides detailed information about CIDR ranges, including the first IP, last IP, and total number of hosts.
- **Overlap Detection**: Identifies overlapping CIDRs and calculates the overlapping range and number of overlapping hosts.
- **REST API**: Exposes functionality via a REST API for easy integration into other systems or automation workflows.

## Use Cases

- **Cloud Infrastructure**: Manage CIDR ranges in cloud environments (e.g., AWS VPCs, Azure VNets) to prevent conflicts.
- **Network Design**: Validate IP address allocation plans and avoid overlapping subnets.
- **Security Audits**: Detect overlapping CIDRs in firewall rules or VPN configurations.
- **DevOps Automation**: Integrate into CI/CD pipelines to validate network configurations before deployment.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/mshumayl/cidr-checkr.git
cd cidr-checkr
```

2. Build the project:
```bash
go build ./...
```

3. Run the server:
```bash
go run cmd/api/main.go
```

The server will start on http://localhost:8080.

## API Endpoints
_Analyze CIDRs_
Endpoint: `/api/analyze-cidrs`
Method: `POST`
Description: Analyzes a list of CIDRs and returns details about each CIDR and any overlaps.

Request Body:
```json
{
  "cidrs": ["192.168.1.0/24", "10.0.0.0/8"]
}
```

Response:
```json
{
  "cidr_details": [
    {
      "cidr": "192.168.1.0/24",
      "first_ip": "192.168.1.0",
      "last_ip": "192.168.1.255",
      "total_hosts": 254
    },
    {
      "cidr": "10.0.0.0/8",
      "first_ip": "10.0.0.0",
      "last_ip": "10.255.255.255",
      "total_hosts": 16777214
    }
  ],
  "overlaps": [
    {
      "cidr1": "192.168.1.0/24",
      "cidr2": "192.168.1.0/25",
      "overlap_range": "192.168.1.0 - 192.168.1.127",
      "overlap_hosts": 128
    }
  ],
  "has_collision": true
}
```

## Running Tests
To run the unit tests, use the following command:
```bash
go test ./...
```

## Project Structure
```
cidr-checkr/
├── cmd/
│   └── api/
│       └── main.go          # Entry point for the REST API server
├── internal/
│   ├── handlers/
│   │   ├── handlers.go      # HTTP handlers for the API
│   │   └── handlers_test.go # Unit tests for the handlers
│   ├── models/
│   │   └── models.go        # Data models for the application
│   └── service/
│       ├── analyzer.go      # Core logic for CIDR analysis
│       └── analyzer_test.go # Unit tests for the analyzer
└── go.mod                   # Go module file
```

## Contributing
Contributions are welcome! If you have ideas for new features or improvements, feel free to open an issue or submit a pull request.