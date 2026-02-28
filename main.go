package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/row"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/props"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	colorBlue     = &props.Color{Red: 0, Green: 60, Blue: 120}
	colorWhite    = &props.Color{Red: 255, Green: 255, Blue: 255}
	colorLightGray = &props.Color{Red: 245, Green: 245, Blue: 245}
	colorGray     = &props.Color{Red: 150, Green: 150, Blue: 150}
	colorRed      = &props.Color{Red: 180, Green: 0, Blue: 0}
	colorHigh     = &props.Color{Red: 255, Green: 100, Blue: 0}
	colorMed      = &props.Color{Red: 255, Green: 200, Blue: 0}
	colorLow      = &props.Color{Red: 0, Green: 150, Blue: 0}
)

// TrivyReport represents the JSON output from Trivy
type TrivyReport struct {
	SchemaVersion int    `json:"SchemaVersion"`
	ArtifactName  string `json:"ArtifactName"`
	ArtifactType  string `json:"ArtifactType"`
	Metadata      struct {
		ImageConfig struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		} `json:"ImageConfig"`
	} `json:"Metadata"`
	Results []TrivyResult `json:"Results"`
}

type TrivyResult struct {
	Target            string               `json:"Target"`
	Class             string               `json:"Class"`
	Type              string               `json:"Type"`
	Packages          []TrivyPackage       `json:"Packages"`
	Vulnerabilities   []TrivyVulnerability `json:"Vulnerabilities"`
	Misconfigurations []TrivyMisconfig     `json:"Misconfigurations"`
	Secrets           []TrivySecret        `json:"Secrets"`
}


type TrivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	Severity         string   `json:"Severity"`
	References       []string `json:"References"`
	CVSS           map[string]struct {
		V3Score float64 `json:"V3Score"`
		V2Score float64 `json:"V2Score"`
	} `json:"CVSS"`
	VendorCVSS map[string]struct {
		V3Score float64 `json:"V3Score"`
		V2Score float64 `json:"V2Score"`
	} `json:"VendorCVSS"`
	EPSS *struct {
		Score      float64 `json:"Score"`
		Percentile float64 `json:"Percentile"`
	} `json:"EPSS"`
	CWEIDs   []string `json:"CWEIDs"`
	Exploits []string `json:"Exploits"`
}

type TrivyMisconfig struct {
	Type        string `json:"Type"`
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Message     string `json:"Message"`
	Severity    string `json:"Severity"`
	Status      string `json:"Status"`
}

type TrivySecret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	Match     string `json:"Match"`
	Line      int    `json:"Line"`
}

func main() {
	var from string
	var output string
	var reportTitle string
	var withEpss bool
	var withExploits bool

	var rootCmd = &cobra.Command{
		Use:   "trivy-pdf [COMMAND] [TARGET] [OUTPUT]",
		Short: "Generate PDF report from Trivy scans or JSON results",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// If we have "generate" subcommand, it's handled by that.
			// Otherwise, we might be receiving a scan command.
			
			if len(args) == 0 {
				return cmd.Help()
			}

			// Traditional scan pattern: command target filename
			// Example: trivy pdf image alpine:latest report
			if from == "" && len(args) >= 2 {
				// Handle output filename if not provided by flag
				
				// Let's try to match standard subcommand logic.
				
				// If we have flags, find where --pdf-flags starts?
				// For now, let's keep it simple: if from is empty, we run a scan.
				
				scanCmd := args[0]
				target := args[1]
				
				// Handle output filename from args if not provided by flag
				if output == "" && len(args) == 3 {
					output = args[2]
				} else if output == "" {
					output = "report.pdf"
				}

				return runScanAndGenerate(scanCmd, target, output, reportTitle, cmd.Flags())
			}

			// If "from" is set, the "generate" behavior is expected.
			if from != "" {
				files := strings.Split(from, ",")
				return processFilesAndGenerate(files, output, reportTitle)
			}

			return fmt.Errorf("invalid arguments. Use --from for existing JSON files or provide scan command and target")
		},
	}

	rootCmd.PersistentFlags().StringVar(&from, "from", "", "Comma separated json scan result files")
	rootCmd.PersistentFlags().StringVar(&output, "output", "", "Report name")
	rootCmd.PersistentFlags().StringVar(&reportTitle, "report-title", "Trivy Scan Report", "Report Title")
	rootCmd.PersistentFlags().BoolVar(&withEpss, "with-epss", false, "Include EPSS data (ignored)")
	rootCmd.PersistentFlags().BoolVar(&withExploits, "with-exploits", false, "Include Exploits (ignored)")
	rootCmd.PersistentFlags().String("report", "", "Report type (ignored)")

	// Subcommand "generate"
	var generateCmd = &cobra.Command{
		Use:   "generate",
		Short: "Generate report from existing JSON files",
		RunE: func(cmd *cobra.Command, args []string) error {
			if from == "" {
				return fmt.Errorf("the --from flag is required for generate")
			}
			files := strings.Split(from, ",")
			if output == "" {
				output = "report.pdf"
			}
			return processFilesAndGenerate(files, output, reportTitle)
		},
	}
	
	// Scan subcommands
	scanRunE := func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("target is required (e.g., image name or path)")
		}
		target := args[0]
		
		// If output is not set via flag, check if it's passed as second arg
		if output == "" {
			if len(args) >= 2 {
				output = args[1]
			} else {
				output = "report.pdf"
			}
		}
		
		return runScanAndGenerate(cmd.Name(), target, output, reportTitle, cmd.Flags())
	}

	var imageCmd = &cobra.Command{Use: "image", Short: "Scan a container image", RunE: scanRunE}
	var fsCmd = &cobra.Command{Use: "fs", Short: "Scan a local filesystem", RunE: scanRunE}
	var k8sCmd = &cobra.Command{Use: "k8s", Short: "Scan a kubernetes cluster", RunE: scanRunE}

	rootCmd.AddCommand(generateCmd, imageCmd, fsCmd, k8sCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func runScanAndGenerate(scanCmd, target, outputPath, title string, flags *pflag.FlagSet) error {
	tmpFile := "trivy_scan_output.json"
	defer os.Remove(tmpFile)

	fmt.Printf("Running trivy %s scan on %s...\n", scanCmd, target)
	
	// Prepare trivy arguments
	trivyArgs := []string{scanCmd, "--list-all-pkgs", "--format", "json", "--output", tmpFile, target}
	
	// Run trivy
	tcmd := exec.Command("trivy", trivyArgs...)
	tcmd.Stdout = os.Stdout
	tcmd.Stderr = os.Stderr
	
	if err := tcmd.Run(); err != nil {
		return fmt.Errorf("trivy scan failed: %w", err)
	}

	return processFilesAndGenerate([]string{tmpFile}, outputPath, title)
}

type SPDXReport struct {
	SPDXVersion       string `json:"spdxVersion"`
	DataLicense       string `json:"dataLicense"`
	SPDXID            string `json:"SPDXID"`
	Name              string `json:"name"`
	DocumentNamespace string `json:"documentNamespace"`
	CreationInfo      struct {
		Creators []string `json:"creators"`
		Created  string   `json:"created"`
	} `json:"creationInfo"`
	Packages []struct {
		Name             string `json:"name"`
		SPDXID           string `json:"SPDXID"`
		VersionInfo      string `json:"versionInfo"`
		LicenseDeclared  string `json:"licenseDeclared"`
		LicenseConcluded string `json:"licenseConcluded"`
		FilesAnalyzed    bool   `json:"filesAnalyzed"`
	} `json:"packages"`
}

type TrivyPackage struct {
	Name             string `json:"Name"`
	SPDXID           string `json:"SPDXID,omitempty"`
	Version          string `json:"Version"`
	Release          string `json:"Release"`
	Arch             string `json:"Arch"`
	License          string `json:"License"`
	LicenseDeclared  string `json:"LicenseDeclared,omitempty"`
	LicenseConcluded string `json:"LicenseConcluded,omitempty"`
	FilesAnalyzed    string `json:"FilesAnalyzed,omitempty"`
}

func processFilesAndGenerate(files []string, outputPath, title string) error {
	var allReports []TrivyReport

	for _, file := range files {
		file = strings.TrimSpace(file)
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", file, err)
		}

		// Try standard Trivy Report
		var report TrivyReport
		if err := json.Unmarshal(data, &report); err == nil && report.SchemaVersion > 0 {
			allReports = append(allReports, report)
			continue
		}

		// Try SPDX-JSON
		var spdx SPDXReport
		if err := json.Unmarshal(data, &spdx); err == nil && spdx.SPDXVersion != "" {
			// Convert SPDX to Trivy format for rendering
			converted := TrivyReport{
				ArtifactName: spdx.Name,
				ArtifactType: "SBOM (SPDX)",
				Metadata: struct {
					ImageConfig struct {
						Architecture string `json:"architecture"`
						OS           string `json:"os"`
					} `json:"ImageConfig"`
				}{},
				Results: []TrivyResult{
					{
						Target: spdx.Name,
						Type:   fmt.Sprintf("%s | %s | %s | %s", spdx.SPDXVersion, spdx.DataLicense, spdx.SPDXID, spdx.DocumentNamespace),
						Class:  fmt.Sprintf("%s | %s", strings.Join(spdx.CreationInfo.Creators, ", "), spdx.CreationInfo.Created),
					},
				},
			}
			for i, p := range spdx.Packages {
				if i == 0 && p.Name == spdx.Name {
					continue // Skip root package
				}
				converted.Results[0].Packages = append(converted.Results[0].Packages, TrivyPackage{
					Name:             p.Name,
					SPDXID:           p.SPDXID,
					Version:          p.VersionInfo,
					LicenseConcluded: p.LicenseConcluded,
					LicenseDeclared:  p.LicenseDeclared,
					FilesAnalyzed:    fmt.Sprintf("%v", p.FilesAnalyzed),
				})
			}
			allReports = append(allReports, converted)
			continue
		}

		// Try raw Results array?
		var results []TrivyResult
		if err2 := json.Unmarshal(data, &results); err2 == nil {
			allReports = append(allReports, TrivyReport{Results: results})
			continue
		}
	}

	if outputPath == "" {
		outputPath = "report"
	} else if strings.HasSuffix(outputPath, ".pdf") {
		outputPath = strings.TrimSuffix(outputPath, ".pdf")
	}

	// Always attempt to generate both if data is available
	var finalErr error
	if err := generateSBOMPDF(allReports, title, outputPath+"_sbom.pdf"); err != nil {
		finalErr = err
	}
	if err := generateVulnerabilityPDF(allReports, title, outputPath+"_vulns.pdf"); err != nil {
		if finalErr == nil {
			finalErr = err
		}
	}

	return finalErr
}

func generateSBOMPDF(reports []TrivyReport, title string, outputPath string) error {
	packagesFound := false
	for _, r := range reports {
		for _, res := range r.Results {
			if len(res.Packages) > 0 {
				packagesFound = true
				break
			}
		}
	}

	if !packagesFound {
		return nil
	}

	cfg := config.NewBuilder().WithPageNumber().Build()
	m := maroto.New(cfg)

	// Professional Title Header
	m.AddRows(
		row.New(25).Add(
			col.New(12).Add(
				text.New(title, props.Text{
					Top:    8,
					Size:   18,
					Style:  fontstyle.Bold,
					Align:  align.Center,
					Color:  colorWhite,
				}),
			).WithStyle(&props.Cell{BackgroundColor: colorBlue}),
		),
	)

	for _, report := range reports {
		artifactDrawn := false
		for _, result := range report.Results {
			if len(result.Packages) == 0 {
				continue
			}

			if !artifactDrawn {
				m.AddRows(row.New(5)) // Spacer
				m.AddRows(
					row.New(15).Add(
						col.New(12).Add(
							text.New(report.ArtifactName, props.Text{
								Top:    4,
								Left:   2,
								Size:   12,
								Style:  fontstyle.Bold,
								Color:  colorBlue,
							}),
							text.New("SBOM (Package Inventory)", props.Text{
								Top:    4,
								Right:  2,
								Size:   8,
								Style:  fontstyle.Italic,
								Align:  align.Right,
								Color:  colorGray,
							}),
						).WithStyle(&props.Cell{BackgroundColor: colorLightGray}),
					),
				)
				artifactDrawn = true
			}

			if report.ArtifactType == "SBOM (SPDX)" {
				m.AddRows(
					row.New(10).Add(
						col.New(12).Add(
							text.New(result.Type+" | "+result.Class, props.Text{
								Size:  6,
								Color: colorGray,
								Style: fontstyle.Italic,
								Top:   2,
							}),
						),
					),
				)
			}

			// Table Header with Background
			m.AddRows(row.New(2))
			m.AddRows(
				row.New(10).Add(
					col.New(3).Add(text.New("Package Name", props.Text{Size: 8, Style: fontstyle.Bold, Color: colorWhite, Top: 2, Left: 1})).WithStyle(&props.Cell{BackgroundColor: colorBlue}),
					col.New(3).Add(text.New("SPDXID", props.Text{Size: 8, Style: fontstyle.Bold, Color: colorWhite, Top: 2})).WithStyle(&props.Cell{BackgroundColor: colorBlue}),
					col.New(2).Add(text.New("Version", props.Text{Size: 8, Style: fontstyle.Bold, Color: colorWhite, Top: 2})).WithStyle(&props.Cell{BackgroundColor: colorBlue}),
					col.New(1).Add(text.New("Files", props.Text{Size: 8, Style: fontstyle.Bold, Color: colorWhite, Top: 2})).WithStyle(&props.Cell{BackgroundColor: colorBlue}),
					col.New(3).Add(text.New("License", props.Text{Size: 8, Style: fontstyle.Bold, Color: colorWhite, Top: 2})).WithStyle(&props.Cell{BackgroundColor: colorBlue}),
				),
			)

			for i, p := range result.Packages {
				license := p.LicenseConcluded
				if license == "" || license == "NOASSERTION" {
					license = p.LicenseDeclared
				}
				
				var cellStyle *props.Cell
				if i%2 == 0 {
					cellStyle = &props.Cell{BackgroundColor: colorLightGray}
				}

				h := resultRowHeight(p.Name)
				m.AddRows(
					row.New(h).Add(
						col.New(3).Add(text.New(p.Name, props.Text{Size: 7, Left: 1, Top: 1})).WithStyle(cellStyle),
						col.New(3).Add(text.New(p.SPDXID, props.Text{Size: 7, Top: 1})).WithStyle(cellStyle),
						col.New(2).Add(text.New(p.Version, props.Text{Size: 7, Top: 1})).WithStyle(cellStyle),
						col.New(1).Add(text.New(p.FilesAnalyzed, props.Text{Size: 7, Top: 1})).WithStyle(cellStyle),
						col.New(3).Add(text.New(license, props.Text{Size: 7, Top: 1})).WithStyle(cellStyle),
					),
				)
			}
			m.AddRows(row.New(5))
		}
	}

	doc, err := m.Generate()
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, doc.GetBytes(), 0644)
}

func generateVulnerabilityPDF(reports []TrivyReport, title string, outputPath string) error {
	cfg := config.NewBuilder().WithPageNumber().Build()
	m := maroto.New(cfg)

	critCount, highCount, medCount, lowCount, negCount := 0, 0, 0, 0, 0
	vulnFound := false

	for _, report := range reports {
		for _, result := range report.Results {
			for _, v := range result.Vulnerabilities {
				vulnFound = true
				switch strings.ToUpper(v.Severity) {
				case "CRITICAL": critCount++
				case "HIGH": highCount++
				case "MEDIUM": medCount++
				case "LOW": lowCount++
				default: negCount++
				}
			}
		}
	}

	if !vulnFound {
		return nil
	}

	// Professional Header
	m.AddRows(
		row.New(25).Add(
			col.New(12).Add(
				text.New("Vulnerability Security Audit", props.Text{
					Top:    8,
					Size:   18,
					Style:  fontstyle.Bold,
					Align:  align.Center,
					Color:  colorWhite,
				}),
			).WithStyle(&props.Cell{BackgroundColor: colorBlue}),
		),
	)

	m.AddRows(row.New(5))

	// Summary Cards
	m.AddRows(
		row.New(12).Add(
			col.New(2).Add(text.New(fmt.Sprintf("CRIT: %d", critCount), props.Text{Size: 9, Style: fontstyle.Bold, Color: colorWhite, Align: align.Center, Top: 3})).WithStyle(&props.Cell{BackgroundColor: colorRed}),
			col.New(1),
			col.New(2).Add(text.New(fmt.Sprintf("HIGH: %d", highCount), props.Text{Size: 9, Style: fontstyle.Bold, Color: colorWhite, Align: align.Center, Top: 3})).WithStyle(&props.Cell{BackgroundColor: colorHigh}),
			col.New(1),
			col.New(2).Add(text.New(fmt.Sprintf("MED: %d", medCount), props.Text{Size: 9, Style: fontstyle.Bold, Color: colorWhite, Align: align.Center, Top: 3})).WithStyle(&props.Cell{BackgroundColor: colorMed}),
			col.New(1),
			col.New(2).Add(text.New(fmt.Sprintf("LOW: %d", lowCount), props.Text{Size: 9, Style: fontstyle.Bold, Color: colorWhite, Align: align.Center, Top: 3})).WithStyle(&props.Cell{BackgroundColor: colorLow}),
			col.New(1).Add(text.New("via trivy-pdf", props.Text{Size: 6, Style: fontstyle.Italic, Align: align.Right, Top: 8, Color: colorGray})),
		),
	)

	m.AddRows(row.New(5))

	// Table Header
	m.AddRows(
		row.New(10).Add(
			col.New(2).Add(text.New("Target", props.Text{Size: 8, Style: fontstyle.Bold, Color: colorWhite, Top: 2, Left: 1})).WithStyle(&props.Cell{BackgroundColor: colorBlue}),
			col.New(2).Add(text.New("Package", props.Text{Size: 8, Style: fontstyle.Bold, Color: colorWhite, Top: 2})).WithStyle(&props.Cell{BackgroundColor: colorBlue}),
			col.New(2).Add(text.New("ID", props.Text{Size: 8, Style: fontstyle.Bold, Color: colorWhite, Top: 2})).WithStyle(&props.Cell{BackgroundColor: colorBlue}),
			col.New(1).Add(text.New("Score", props.Text{Size: 8, Style: fontstyle.Bold, Color: colorWhite, Top: 2})).WithStyle(&props.Cell{BackgroundColor: colorBlue}),
			col.New(1).Add(text.New("EPSS", props.Text{Size: 8, Style: fontstyle.Bold, Color: colorWhite, Top: 2})).WithStyle(&props.Cell{BackgroundColor: colorBlue}),
			col.New(1).Add(text.New("Sev", props.Text{Size: 8, Style: fontstyle.Bold, Color: colorWhite, Top: 2})).WithStyle(&props.Cell{BackgroundColor: colorBlue}),
			col.New(1).Add(text.New("Fixed", props.Text{Size: 8, Style: fontstyle.Bold, Color: colorWhite, Top: 2})).WithStyle(&props.Cell{BackgroundColor: colorBlue}),
			col.New(2).Add(text.New("Title", props.Text{Size: 8, Style: fontstyle.Bold, Color: colorWhite, Top: 2})).WithStyle(&props.Cell{BackgroundColor: colorBlue}),
		),
	)

	idx := 0
	for _, report := range reports {
		for _, result := range report.Results {
			for _, v := range result.Vulnerabilities {
				score := "n/a"
				if nvd, ok := v.CVSS["nvd"]; ok {
					if nvd.V3Score > 0 { score = fmt.Sprintf("%.1f", nvd.V3Score) } else { score = fmt.Sprintf("%.1f", nvd.V2Score) }
				} else if nvd, ok := v.VendorCVSS["nvd"]; ok {
					if nvd.V3Score > 0 { score = fmt.Sprintf("%.1f", nvd.V3Score) }
				}
				
				epssStr := "n/a"
				if v.EPSS != nil { epssStr = fmt.Sprintf("%.2f", v.EPSS.Score) }

				var cellStyle *props.Cell
				if idx%2 == 0 { cellStyle = &props.Cell{BackgroundColor: colorLightGray} }
				idx++

				h := resultRowHeight(v.Title)
				m.AddRows(
					row.New(h).Add(
						col.New(2).Add(text.New(result.Target, props.Text{Size: 6, Left: 1, Top: 1})).WithStyle(cellStyle),
						col.New(2).Add(text.New(v.PkgName, props.Text{Size: 6, Top: 1, Style: fontstyle.Bold})).WithStyle(cellStyle),
						col.New(2).Add(text.New(v.VulnerabilityID, props.Text{Size: 6, Top: 1, Color: colorBlue})).WithStyle(cellStyle),
						col.New(1).Add(text.New(score, props.Text{Size: 6, Top: 1})).WithStyle(cellStyle),
						col.New(1).Add(text.New(epssStr, props.Text{Size: 6, Top: 1})).WithStyle(cellStyle),
						col.New(1).Add(text.New(v.Severity, props.Text{Size: 6, Top: 1, Style: fontstyle.Bold, Color: getSeverityColor(v.Severity)})).WithStyle(cellStyle),
						col.New(1).Add(text.New(v.FixedVersion, props.Text{Size: 6, Top: 1})).WithStyle(cellStyle),
						col.New(2).Add(text.New(v.Title, props.Text{Size: 6, Top: 1})).WithStyle(cellStyle),
					),
				)
			}
		}
	}

	doc, err := m.Generate()
	if err != nil { return err }
	return os.WriteFile(outputPath, doc.GetBytes(), 0644)
}

func resultRowHeight(s string) float64 {
	length := len(s)
	if length > 50 { return 14.0 }
	if length > 25 { return 10.0 }
	return 7.0
}

func getSeverityColor(severity string) *props.Color {
	switch strings.ToUpper(severity) {
	case "CRITICAL": return colorRed
	case "HIGH": return colorHigh
	case "MEDIUM": return colorMed
	case "LOW": return colorLow
	default: return colorGray
	}
}
