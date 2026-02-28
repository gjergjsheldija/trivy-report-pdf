# Trivy PDF Plugin

A professional Trivy plugin that generates high-quality security audit and SBOM reports in PDF format.

## Installation

```bash
trivy plugin install github.com/gjergjsheldija/trivy-report-pdf
```

### Local Development
1. Clone the repository: `git clone https://github.com/gjergjsheldija/trivy-report-pdf.git`
2. Build the binary: `go build -o trivy-pdf main.go`
3. Install as a local plugin: `trivy plugin install .`

## Usage

The plugin generates two distinct, professional reports for every scan:
1. `*_sbom.pdf`: A complete package inventory/SBOM.
2. `*_vulns.pdf`: A security audit with vulnerability details and summary cards.

### Generate from existing JSON results
```bash
trivy pdf generate --from report.json --output audit_report --report-title "Enterprise Security Scan"
```

### Scan and generate PDF directly
```bash
trivy pdf image alpine:latest --output my_scan
```
*(Generates `my_scan_sbom.pdf` and `my_scan_vulns.pdf`)*

## Features

- **Professional Audit Aesthetic**: Enterprise-themed headers, high-readability zebra-striped tables, and clean typography.
- **Security Dashboard**: Vulnerability reports feature color-coded summary cards (Critical/High/Medium/Low) for immediate risk assessment.
- **Dual-Mode Reporting**: Separate, specialized documents for compliance (SBOM) and security (Vulnerabilities).
- **SPDX Support**: Built-in support for converting standard SPDX-JSON files into professional PDF inventories.
- **Rich Data**: Includes NVD scores, EPSS scores, fixed versions, and detailed severity badges.

## Flags

* `--from`: Comma separated JSON scan result files (standard Trivy or SPDX-JSON).
* `--output`: Prefix for the output PDF files (e.g., `audit`).
* `--report-title`: Custom title displayed at the top of the PDF.

## Development

Requires Go 1.22+.

```bash
go build -o trivy-pdf
```
