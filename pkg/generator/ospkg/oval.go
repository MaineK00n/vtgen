package ospkg

import (
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/MaineK00n/vtgen/pkg/generator/log"
	"github.com/MaineK00n/vtgen/pkg/generator/util"
	ovalmodels "github.com/vulsio/goval-dictionary/models"
)

func getAllCvesInOVAL(os, release string, db *gorm.DB) ([]string, error) {
	family, osVer, err := formatFamilyAndOSVerInOval(os, release)
	if err != nil {
		return nil, fmt.Errorf("failed to formatFamilyAndOSVerInOval: %w", err)
	}

	cves := []string{}
	if err := db.
		Model(&ovalmodels.Definition{}).
		Joins("JOIN roots ON roots.id = definitions.root_id AND roots.family= ? AND roots.os_version = ?", family, osVer).
		Joins("JOIN advisories ON advisories.definition_id = definitions.id").
		Joins("JOIN cves ON cves.advisory_id = advisories.id").Select("cves.cve_id").Find(&cves).Error; err != nil {
		return nil, fmt.Errorf("failed to Find cves: %w", err)
	}
	return cves, nil
}

func getPackagebyCVEIDsInOVAL(os, release, arch string, cveIDs []string, db *gorm.DB) (map[string]map[string][]string, error) {
	log.Logger.Infow("start getPackagebyCVEIDsInOVAL", "os", os, "release", release, "arch", arch)

	family, osVer, err := formatFamilyAndOSVerInOval(os, release)
	if err != nil {
		return nil, fmt.Errorf("failed to formatFamilyAndOSVerInOval: %w", err)
	}

	defs := []ovalmodels.Definition{}
	for idx := range util.ChunkSlice(len(cveIDs), 100) {
		tmpDefs := []ovalmodels.Definition{}
		q := db.
			Joins("JOIN roots ON roots.id = definitions.root_id AND roots.family= ? AND roots.os_version = ?", family, osVer).
			Joins("JOIN advisories ON advisories.definition_id = definitions.id").
			Joins("JOIN cves ON cves.advisory_id = advisories.id").
			Where("cves.cve_id IN ?", cveIDs[idx.From:idx.To]).
			Preload("Advisory").
			Preload("Advisory.Cves", "cve_id IN ?", cveIDs[idx.From:idx.To])
		if arch == "" {
			q = q.Preload("AffectedPacks")
		} else {
			q = q.Preload("AffectedPacks", "arch = ?", arch)
		}
		if err := q.Find(&tmpDefs).Error; err != nil {
			return nil, fmt.Errorf("failed to Find definitions: %w", err)
		}
		defs = append(defs, tmpDefs...)
	}

	ovalPkgs := map[string][]ovalmodels.Package{}
	for _, def := range defs {
		if family == "redhat" {
			pkgs := filterByRedHatMajor(def.AffectedPacks, osVer)
			for _, cve := range def.Advisory.Cves {
				ovalPkgs[cve.CveID] = append(ovalPkgs[cve.CveID], pkgs...)
			}
		} else {
			for _, cve := range def.Advisory.Cves {
				ovalPkgs[cve.CveID] = append(ovalPkgs[cve.CveID], def.AffectedPacks...)
			}
		}
	}

	pkgVersions := map[string]map[string][]string{}
	for cveID, pkgs := range ovalPkgs {
		pkgVersions[cveID] = map[string][]string{}
		for _, pkg := range pkgs {
			log.Logger.Debugw("OVAL Package Info", "Name", pkg.Name, "NotFixedYet", pkg.NotFixedYet, "version", pkg.Version)

			version := pkg.Version
			if pkg.NotFixedYet {
				version = TmpVer
			}
			if version == "" {
				continue
			}
			pkgVersions[cveID][pkg.Name] = append(pkgVersions[cveID][pkg.Name], version)
		}
	}

	return pkgVersions, nil
}

func formatFamilyAndOSVerInOval(os, release string) (string, string, error) {
	switch strings.ToLower(os) {
	case "debian", "raspbian":
		return "debian", major(release), nil
	case "ubuntu":
		return "ubuntu", major(release), nil
	case "redhat", "centos", "alma", "rocky":
		return "redhat", major(release), nil
	case "oracle":
		return "oracle", major(release), nil
	case "alpine":
		return "alpine", majorDotMinor(release), nil
	case "amazon":
		return "amazon", getAmazonLinux1or2(release), nil
	default:
		return "", "", fmt.Errorf("not supported os: %s", os)
	}
}

func filterByRedHatMajor(packs []ovalmodels.Package, majorVer string) (filtered []ovalmodels.Package) {
	for _, p := range packs {
		if strings.Contains(p.Version, ".el"+majorVer) ||
			strings.Contains(p.Version, ".module+el"+majorVer) {
			filtered = append(filtered, p)
		}
	}
	return
}
