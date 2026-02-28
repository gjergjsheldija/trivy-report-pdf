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

The following flags can be used with any scan command (`image`, `fs`, `k8s`) or the `generate` command:

*   **`--output`** (or positional): The prefix for the output PDF files. If you provide `audit`, the plugin generates `audit_sbom.pdf` and `audit_vulns.pdf`. (Default: `report`).
*   **`--report-title`**: Custom title displayed at the top of the generated PDF reports. (Default: `Trivy Scan Report`).
*   **`--from`**: (Required for `generate`) Comma-separated list of existing Trivy JSON or SPDX-JSON result files to process.
*   **`--with-epss`**: Include EPSS scores in the report. (Note: Currently always enabled in the visual audit if data is present).
*   **`--with-exploits`**: Include exploit information in the report. (Note: Currently a placeholder for future detailed exploit mapping).
*   **`--report`**: Specifies report type. (Note: Currently a placeholder for standardizing output formats).

## Development

Requires Go 1.22+.

```bash
go build -o trivy-pdf
```
