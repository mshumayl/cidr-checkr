# cidr-checkr

`cidr-checkr` is a lightweight HTTP API for analyzing CIDR ranges, detecting overlaps, and gaining quick insights into IP address space. It's built for network engineers, security teams, and DevOps professionals who want to improve efficiency over manual CIDR calculations and IP lookups.

By automating IP math and conflict detection, `cidr-checkr` helps validate subnets, prevent misconfigurations, and manage complex network topologies with confidence.

Delivered as a headless API server, it integrates seamlessly into CI/CD pipelines, infrastructure-as-code workflows, or any custom automation system.

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
git clone https://github.com/your-username/cidr-checkr.git
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