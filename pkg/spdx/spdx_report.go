package spdx

import (
	"fmt"
	"os"
	"strings"
	"bytes"
	"reflect"
	"errors"

	"github.com/ebay/sbom-scorecard/pkg/scorecard"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/tagvalue"
	"github.com/spdx/tools-golang/rdf"

	"regexp"
)

var isNumeric = regexp.MustCompile(`\d`)
var EmptyDocument = spdx.Document{}

var missingPackages = scorecard.ReportValue{
	Ratio:     0,
	Reasoning: "No packages",
}

type SpdxReport struct {
	doc      spdx.Document
	docError error
	valid    bool

	totalPackages int
	totalFiles    int
	hasLicense    int
	hasPackDigest int
	hasPurl       int
	hasCPE        int
	hasPurlOrCPE  int
	hasFileDigest int
	hasPackVer    int
}

func (r *SpdxReport) Metadata() scorecard.ReportMetadata {
	return scorecard.ReportMetadata{
		TotalPackages: r.totalPackages,
	}
}

func (r *SpdxReport) Report() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d total packages\n", r.totalPackages))
	sb.WriteString(fmt.Sprintf("%d total files\n", r.totalFiles))
	sb.WriteString(fmt.Sprintf("%d%% have licenses.\n", scorecard.PrettyPercent(r.hasLicense, r.totalPackages)))
	sb.WriteString(fmt.Sprintf("%d%% have package digest.\n", scorecard.PrettyPercent(r.hasPackDigest, r.totalPackages)))
	sb.WriteString(fmt.Sprintf("%d%% have package versions.\n", scorecard.PrettyPercent(r.hasPackVer, r.totalPackages)))
	sb.WriteString(fmt.Sprintf("%d%% have purls.\n", scorecard.PrettyPercent(r.hasPurl, r.totalPackages)))
	sb.WriteString(fmt.Sprintf("%d%% have CPEs.\n", scorecard.PrettyPercent(r.hasCPE, r.totalPackages)))
	sb.WriteString(fmt.Sprintf("%d%% have file digest.\n", scorecard.PrettyPercent(r.hasFileDigest, r.totalFiles)))
	sb.WriteString(fmt.Sprintf("Spec valid? %v\n", r.valid))
	sb.WriteString(fmt.Sprintf("Has creation info? %v\n", r.CreationInfo().Ratio == 1))

	return sb.String()
}

func (r *SpdxReport) IsSpecCompliant() scorecard.ReportValue {
	if r.docError != nil {
		return scorecard.ReportValue{
			Ratio:     0,
			Reasoning: r.docError.Error(),
		}
	}
	return scorecard.ReportValue{Ratio: 1}
}

func (r *SpdxReport) PackageIdentification() scorecard.ReportValue {
	if r.totalPackages == 0 {
		return missingPackages
	}
	purlPercent := scorecard.PrettyPercent(r.hasPurl, r.totalPackages)
	cpePercent := scorecard.PrettyPercent(r.hasCPE, r.totalPackages)
	either := scorecard.PrettyPercent(r.hasPurlOrCPE, r.totalPackages)
	return scorecard.ReportValue{
		// What percentage has both Purl & CPEs?
		Ratio:     float32(r.hasPurlOrCPE) / float32(r.totalPackages),
		Reasoning: fmt.Sprintf("%d%% have either purls (%d%%) or CPEs (%d%%)", either, purlPercent, cpePercent),
	}
}

func (r *SpdxReport) PackageVersions() scorecard.ReportValue {
	if r.totalPackages == 0 {
		return scorecard.ReportValue{
			Ratio:     0,
			Reasoning: "No packages",
		}
	}
	return scorecard.ReportValue{
		Ratio: float32(r.hasPackVer) / float32(r.totalPackages),
	}
}

func (r *SpdxReport) PackageLicenses() scorecard.ReportValue {
	if r.totalPackages == 0 {
		return scorecard.ReportValue{
			Ratio:     0,
			Reasoning: "No packages",
		}
	}
	return scorecard.ReportValue{
		Ratio: float32(r.hasLicense) / float32(r.totalPackages),
	}
}

func (r *SpdxReport) CreationInfo() scorecard.ReportValue {
	foundTool := false
	hasVersion := false

	if reflect.DeepEqual(r.doc, EmptyDocument) || r.doc.CreationInfo == nil {
		return scorecard.ReportValue{
			Ratio:     0,
			Reasoning: "No creation info found",
		}
	}

	for _, creator := range r.doc.CreationInfo.Creators {
		if creator.CreatorType == "Tool" {
			foundTool = true
			if isNumeric.MatchString(creator.Creator) {
				hasVersion = true
			}
		}
	}

	if !foundTool {
		return scorecard.ReportValue{
			Ratio:     0,
			Reasoning: "No tool was used to create the sbom",
		}
	}

	var score float32
	score = 1.0
	reasons := []string{}

	if !hasVersion {
		score -= .2
		reasons = append(reasons, "The tool used to create the sbom does not have a version")
	}

	if r.doc.CreationInfo.Created == "" {
		score -= .2
		reasons = append(reasons, "There is no timestamp for when the sbom was created")
	}

	return scorecard.ReportValue{
		Ratio:     score,
		Reasoning: strings.Join(reasons, ", "),
	}

}

func LoadDocument(path string) (*spdx.Document, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening SPDX document: %w", err)
	}

	doc, err := json.Read(bytes.NewReader(f))
	if err != nil {
		doc, err = tagvalue.Read(bytes.NewReader(f))
		if err != nil {
			return rdf.Read(bytes.NewReader(f))
		}
	}
	if reflect.DeepEqual(doc, EmptyDocument) {
		return doc, errors.New("Parsed the file, but was unable to find an SBOM in it")
	}
	return doc, err
}

func GetSpdxReport(filename string) scorecard.SbomReport {
	sr := SpdxReport{}
	doc, err := LoadDocument(filename)
	if err != nil {
		fmt.Printf("loading document: %v\n", err)
		sr.docError = err
		return &sr
	}

	sr.doc = *doc
	sr.docError = err

	sr.valid = err == nil
	if !reflect.DeepEqual(sr.doc, EmptyDocument) {
		packages := sr.doc.Packages

		for _, p := range packages {
			sr.totalPackages += 1
			if p.PackageLicenseConcluded != "NONE" &&
				p.PackageLicenseConcluded != "NOASSERTION" &&
				p.PackageLicenseConcluded != "" {
				sr.hasLicense += 1
			} else if p.PackageLicenseDeclared != "NONE" &&
				p.PackageLicenseDeclared != "NOASSERTION" &&
				p.PackageLicenseDeclared != "" {
				sr.hasLicense += 1
			}

			if len(p.PackageChecksums) > 0 {
				sr.hasPackDigest += 1
			}

			var foundCPE bool
			var foundPURL bool
			for _, ref := range p.PackageExternalReferences {
				if !foundPURL && ref.RefType == spdx.PackageManagerPURL {
					sr.hasPurl += 1
					foundPURL = true
				}

				if !foundCPE && strings.HasPrefix(ref.RefType, "cpe") {
					sr.hasCPE += 1
					foundCPE = true
				}
			}
			if foundCPE && foundPURL {
				sr.hasPurlOrCPE += 1
			}

			if p.PackageVersion != "" {
				sr.hasPackVer += 1
			}
		}

		for _, file := range sr.doc.Files {
			sr.totalFiles += 1
			if len(file.Checksums) > 0 {
				sr.hasFileDigest += 1
			}
		}
	}
	return &sr
}
