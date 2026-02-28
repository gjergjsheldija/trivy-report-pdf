# Trivy PDF Plugin

A Trivy plugin that generates a PDF report from scan results.
This plugin aims to provide similar functionality and parameters as [scan2html](https://github.com/fatihtokus/scan2html).

## Installation

```bash
trivy plugin install github.com/gjergjsheldija/trivy-pdf
```

*(Note: Currently this is a project on your local machine, to install as a plugin you can point it to the local directory or build it first).*

To install locally:
1. Build the binary: `go build -o trivy-pdf main.go`
2. Ensure `plugin.yaml` is in the same directory.
3. Link or copy to your trivy plugins directory: `~/.trivy/plugins/pdf`

## Usage

### Generate from existing JSON results
```bash
trivy pdf generate --from report.json --output results.pdf --report-title "My Scan Results"
```

### Scan and generate PDF
```bash
trivy pdf image alpine:latest --output report
```
*(Generates `report_sbom.pdf` and `report_vulns.pdf`)*

## Features

- **SBOM Report**: Professional table layout for SPDX-JSON or Trivy Results.
- **Vulnerability Report**: Visual table matching `scan2html` style with severity badges, NVD scores, and EPSS scores.

## Flags

* `--from`: Comma separated JSON scan result files.
* `--output`: Prefix/Name for the output PDF files (e.g. `report`).
* `--report-title`: Title shown at the top of the PDF.
* `--with-epss`: (Placeholder) Include EPSS data in the report.
* `--with-exploits`: (Placeholder) Include Exploits data in the report.

## Development

Requires Go 1.22+.

```bash
go build -o trivy-pdf
```
