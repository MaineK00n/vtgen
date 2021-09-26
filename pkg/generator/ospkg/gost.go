package ospkg

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MaineK00n/vtgen/pkg/generator/log"
	"github.com/MaineK00n/vtgen/pkg/generator/util"
	gostmodels "github.com/vulsio/gost/models"
	"gorm.io/gorm"
)

func getAllCvesInGost(os string, release string, db *gorm.DB) ([]string, error) {
	family, osVer, err := formatFamilyAndOSVerInGost(os, release)
	if err != nil {
		return nil, fmt.Errorf("failed to formatFamilyAndOSVerInGost: %w", err)
	}

	cveids := []string{}
	switch family {
	case "debian":
		q := db.
			Joins("JOIN debian_packages ON debian_packages.debian_cve_id = debian_cves.id").
			Joins("JOIN debian_releases ON debian_releases.debian_package_id = debian_packages.id").
			Where("debian_releases.product_name = ?", osVer).
			Preload("Package")

		cves := []gostmodels.DebianCVE{}
		limit, tmpCves := 998, []gostmodels.DebianCVE{}
		for i := 0; true; i++ {
			err := q.
				Limit(limit).Offset(i * limit).
				Find(&tmpCves).Error
			if err != nil {
				return nil, fmt.Errorf("failed to Find cves: %w", err)
			}
			if len(tmpCves) == 0 {
				break
			}
			cves = append(cves, tmpCves...)
		}

		for _, cve := range cves {
			if len(cve.Package) > 0 {
				cveids = append(cveids, cve.CveID)
			}
		}
	case "ubuntu":
		q := db.
			Joins("JOIN ubuntu_patches ON ubuntu_patches.ubuntu_cve_id = ubuntu_cves.id").
			Joins("JOIN ubuntu_release_patches ON ubuntu_release_patches.ubuntu_patch_id = ubuntu_patches.id").
			Where("ubuntu_release_patches.release_name = ?", osVer).
			Preload("Patches")

		cves := []gostmodels.UbuntuCVE{}
		limit, tmpCves := 998, []gostmodels.UbuntuCVE{}
		for i := 0; true; i++ {
			err := q.
				Limit(limit).Offset(i * limit).
				Find(&tmpCves).Error
			if err != nil {
				return nil, fmt.Errorf("failed to Find cves: %w", err)
			}
			if len(tmpCves) == 0 {
				break
			}
			cves = append(cves, tmpCves...)
		}

		for _, cve := range cves {
			if len(cve.Patches) > 0 {
				cveids = append(cveids, cve.Candidate)
			}
		}
	case "redhat":
		if err := db.
			Model(&gostmodels.RedhatCVE{}).
			Joins("JOIN redhat_package_states ON redhat_package_states.redhat_cve_id = redhat_cves.id").
			Where("redhat_package_states.cpe = ?", osVer).
			Select("redhat_cves.name").Find(&cveids).Error; err != nil {
			return nil, fmt.Errorf("failed to Find cves: %w", err)
		}
	case "":
		return []string{}, nil
	default:
		return nil, fmt.Errorf("not supported family: %s", family)
	}

	return cveids, nil
}

func getPackagebyCVEIDsInGost(os, release string, cveIDs []string, db *gorm.DB) (map[string]map[string][]string, error) {
	log.Logger.Infow("start getPackagebyCVEIDsInGost", "os", os, "release", release)

	family, osVer, err := formatFamilyAndOSVerInGost(os, release)
	if err != nil {
		return nil, fmt.Errorf("failed to formatFamilyAndOSVerInGost: %w", err)
	}

	pkgVersions := map[string]map[string][]string{}
	switch family {
	case "debian":
		cves := []gostmodels.DebianCVE{}
		for idx := range util.ChunkSlice(len(cveIDs), 100) {
			tmpCves := []gostmodels.DebianCVE{}
			if err := db.
				Joins("JOIN debian_packages ON debian_packages.debian_cve_id = debian_cves.id").
				Joins("JOIN debian_releases ON debian_releases.debian_package_id = debian_packages.id").
				Where("debian_cves.cve_id IN ?", cveIDs[idx.From:idx.To]).
				Where("debian_releases.product_name = ?", osVer).
				Preload("Package").
				Preload("Package.Release", "product_name = ?", osVer).
				Find(&tmpCves).Error; err != nil {
				return nil, fmt.Errorf("failed to Find cves: %w", err)
			}
			cves = append(cves, tmpCves...)
		}

		for _, cve := range cves {
			pkgVersions[cve.CveID] = map[string][]string{}
			for _, pack := range cve.Package {
				for _, release := range pack.Release {
					log.Logger.Debugw("Debug Gost Package Info", "Name", pack.PackageName, "status", release.Status, "version", release.Version, "fixedVersion", release.FixedVersion)

					version := ""
					switch release.Status {
					case "resolved":
						if release.FixedVersion == "" {
							log.Logger.Warnw("Fixed version is not described in the patch about Fixed CVE", "OS", os, "Release", release, "CVEID", cve.CveID, "Package", pack.PackageName)
							continue
						}
						// not affected
						if release.FixedVersion == "0" {
							continue
						}
						version = release.FixedVersion
					case "open":
						version = TmpVer
					default:
						return nil, fmt.Errorf("not supported status: %s", release.Status)
					}

					if version == "" {
						str, err := json.Marshal(cve)
						if err != nil {
							return nil, fmt.Errorf("failed to marshal json: %w", err)
						}
						return nil, fmt.Errorf("version is empty, DebianCVE: %s", str)
					}

					pkgVersions[cve.CveID][pack.PackageName] = append(pkgVersions[cve.CveID][pack.PackageName], version)
				}
			}
		}
	case "ubuntu":
		cves := []gostmodels.UbuntuCVE{}
		for idx := range util.ChunkSlice(len(cveIDs), 100) {
			tmpCves := []gostmodels.UbuntuCVE{}
			if err := db.
				Joins("JOIN ubuntu_patches ON ubuntu_patches.ubuntu_cve_id = ubuntu_cves.id").
				Joins("JOIN ubuntu_release_patches ON ubuntu_release_patches.ubuntu_patch_id = ubuntu_patches.id").
				Where("ubuntu_cves.candidate IN ?", cveIDs[idx.From:idx.To]).
				Where("ubuntu_release_patches.release_name = ?", osVer).
				Preload("Patches").
				Preload("Patches.ReleasePatches", "release_name = ?", osVer).
				Find(&tmpCves).Error; err != nil {
				return nil, fmt.Errorf("failed to Find cves: %w", err)
			}
			cves = append(cves, tmpCves...)
		}

		for _, cve := range cves {
			pkgVersions[cve.Candidate] = map[string][]string{}
			for _, patch := range cve.Patches {
				for _, releasePatch := range patch.ReleasePatches {
					log.Logger.Debugw("Debug Gost Package Info", "Name", patch.PackageName, "status", releasePatch.Status, "note", releasePatch.Note)
					version := ""
					switch releasePatch.Status {
					case "released":
						if releasePatch.Note == "" {
							log.Logger.Warnw("Fixed version is not described in the patch about Fixed CVE", "OS", os, "Release", release, "CVEID", cve.Candidate, "Package", patch.PackageName)
							continue
						}
						version = releasePatch.Note
					case "needs-triage", "needed", "pending":
						version = TmpVer
					case "DNE", "ignored", "not-affected", "deferred":
						continue
					default:
						return nil, fmt.Errorf("not supported status: %s", releasePatch.Status)
					}

					if version == "" {
						str, err := json.Marshal(cve)
						if err != nil {
							return nil, fmt.Errorf("failed to marshal json: %w", err)
						}
						return nil, fmt.Errorf("version is empty, UbuntuCVE: %s", str)
					}

					pkgVersions[cve.Candidate][patch.PackageName] = append(pkgVersions[cve.Candidate][patch.PackageName], version)
				}
			}
		}
	case "redhat":
		cves := []gostmodels.RedhatCVE{}
		for idx := range util.ChunkSlice(len(cveIDs), 100) {
			tmpCves := []gostmodels.RedhatCVE{}
			if err := db.
				Joins("JOIN redhat_package_states ON redhat_package_states.redhat_cve_id = redhat_cves.id").
				Where("redhat_cves.name IN ?", cveIDs[idx.From:idx.To]).
				Where("redhat_package_states.cpe = ?", osVer).
				Preload("PackageState", "cpe = ?", osVer).
				Find(&tmpCves).Error; err != nil {
				return nil, fmt.Errorf("failed to Find cves: %w", err)
			}
			cves = append(cves, tmpCves...)
		}

		for _, cve := range cves {
			pkgVersions[cve.Name] = map[string][]string{}
			for _, pack := range cve.PackageState {
				log.Logger.Debugw("Debug Gost Package Info", "Name", pack.PackageName, "status", pack.FixState)
				version := ""
				switch pack.FixState {
				case "Affected":
					version = fmt.Sprintf("%s.el%s", TmpVer, major(release))
				case "Not affected", "New", "Will not fix":
					continue
				default:
					return nil, fmt.Errorf("not supported status: %s", pack.FixState)
				}

				if version == "" {
					str, err := json.Marshal(cve)
					if err != nil {
						return nil, fmt.Errorf("failed to marshal json: %w", err)
					}
					return nil, fmt.Errorf("version is empty, RedHatCVE: %s", str)
				}

				pkgVersions[cve.Name][pack.PackageName] = append(pkgVersions[cve.Name][pack.PackageName], version)
			}
		}
	case "":
		return map[string]map[string][]string{}, nil
	default:
		return nil, fmt.Errorf("not supported family: %s", family)
	}

	return pkgVersions, nil
}

func formatFamilyAndOSVerInGost(os, release string) (string, string, error) {
	switch strings.ToLower(os) {
	case "debian", "raspbian":
		return "debian", debVerCodename[major(release)], nil
	case "ubuntu":
		return "ubuntu", ubuntuVerCodename[strings.ReplaceAll(release, ".", "")], nil
	case "redhat", "centos", "alma", "rocky":
		return "redhat", fmt.Sprintf("cpe:/o:redhat:enterprise_linux:%s", major(release)), nil
	case "oracle", "alpine", "amazon":
		return "", "", nil
	default:
		return "", "", fmt.Errorf("not supported os: %s", os)
	}
}

var debVerCodename = map[string]string{
	"8":  "jessie",
	"9":  "stretch",
	"10": "buster",
	"11": "bullseye",
	"12": "bookworm",
	"13": "trixie",
}

var ubuntuVerCodename = map[string]string{
	"1404": "trusty",
	"1604": "xenial",
	"1804": "bionic",
	"2004": "focal",
	"2010": "groovy",
	"2104": "hirsute",
}
