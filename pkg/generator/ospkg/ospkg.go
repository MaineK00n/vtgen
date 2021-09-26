package ospkg

import (
	"fmt"
	"strings"

	"github.com/MaineK00n/vtgen/pkg/config"
	"github.com/MaineK00n/vtgen/pkg/generator/log"
	"github.com/MaineK00n/vtgen/pkg/generator/util"
	vulsConfig "github.com/future-architect/vuls/config"
	vulsmodels "github.com/future-architect/vuls/models"
	apkver "github.com/knqyf263/go-apk-version"
	debver "github.com/knqyf263/go-deb-version"
	rpmver "github.com/knqyf263/go-rpm-version"
	"gorm.io/gorm"
)

func GenOSPkg(ospkgCnf config.OSPkg, ovalPath, gostPath string) (vulsmodels.ScanResult, error) {
	ovalDB, err := util.NewDB(ovalPath)
	if err != nil {
		return vulsmodels.ScanResult{}, fmt.Errorf("failed to NewDB: %w", err)
	}
	gostDB, err := util.NewDB(gostPath)
	if err != nil {
		return vulsmodels.ScanResult{}, fmt.Errorf("failed to NewDB: %w", err)
	}

	var targetCves []string
	if ospkgCnf.Mode == "specified" {
		targetCves = ospkgCnf.Cves
	} else {
		allCves, err := getAllCves(ospkgCnf.OS, ospkgCnf.Release, ovalDB, gostDB)
		if err != nil {
			return vulsmodels.ScanResult{}, fmt.Errorf("failed to getAllCves: %w", err)
		}
		if ospkgCnf.Mode == "max" {
			targetCves = allCves
		} else {
			targetCves = util.RandomSample(allCves, int(float64(len(allCves))*ospkgCnf.Size))
		}
	}
	log.Logger.Infow("generation CVEID config", "Total CVEs", len(targetCves))
	log.Logger.Debugw("CVEIDs to be generated", "CVEIDs", targetCves)

	// pkgVersions: map[string]map[string][]string: {"CVEID": {"PackageName": ["Version"]}}, max length of a "Version" is 2 (OVAL, Gost)
	pkgVersions, err := getPackagebyCVEID(ospkgCnf.OS, ospkgCnf.Release, ospkgCnf.Arch, targetCves, ovalDB, gostDB)
	if err != nil {
		return vulsmodels.ScanResult{}, fmt.Errorf("failed to getPackagebyCVEID: %w", err)
	}

	// pkgMinVersion: map[string]string: {"PackageName": "Version"}
	pkgMinVersion, err := getPackageMinVersion(ospkgCnf.OS, pkgVersions)
	if err != nil {
		return vulsmodels.ScanResult{}, fmt.Errorf("failed to getPackageMinVersion: %w", err)
	}
	numDropCve := len(targetCves) - len(pkgMinVersion)
	if numDropCve > 0 {
		log.Logger.Infow("some of the CVEIDs could not be reproduced", "Total Drop CVEs", numDropCve)

	}

	installedPkgs, err := convertOneVersionSmaller(ospkgCnf.OS, pkgMinVersion)
	if err != nil {
		return vulsmodels.ScanResult{}, fmt.Errorf("failed to convertOneVersionSmaller: %w", err)
	}

	vulsPkgs, err := convertToVulsPackages(ospkgCnf.OS, installedPkgs)
	if err != nil {
		return vulsmodels.ScanResult{}, fmt.Errorf("failed to convertToVulsPackages: %w", err)
	}

	if err := util.CloseDB(ovalDB); err != nil {
		return vulsmodels.ScanResult{}, fmt.Errorf("failed to CloseDB: %w", err)
	}
	if err := util.CloseDB(gostDB); err != nil {
		return vulsmodels.ScanResult{}, fmt.Errorf("failed to CloseDB: %w", err)
	}

	return vulsmodels.ScanResult{
		JSONVersion:      4,
		Family:           ospkgCnf.OS,
		Release:          ospkgCnf.Release,
		ScanMode:         "fast mode",
		ScannedBy:        "vtgen",
		ScannedVersion:   "v0.18.0",
		ScannedRevision:  "build-20210924_214640_70af368",
		ScannedVia:       "remote",
		IPv4Addrs:        []string{"192.168.0.2", "172.17.0.1"},
		ScannedIPv4Addrs: []string{"192.168.0.2", "172.17.0.1"},
		Packages:         vulsPkgs,
		Config: struct {
			Scan   vulsConfig.Config "json:\"scan\""
			Report vulsConfig.Config "json:\"report\""
		}{
			Scan: vulsConfig.Config{
				OvalDict: vulsConfig.GovalDictConf{
					VulnDict: vulsConfig.VulnDict{
						Type:        "sqlite3",
						SQLite3Path: ovalPath,
					},
				},
				Gost: vulsConfig.GostConf{
					VulnDict: vulsConfig.VulnDict{
						Type:        "sqlite3",
						SQLite3Path: ovalPath,
					},
				},
			},
		},
	}, nil
}

func getAllCves(os, release string, ovalDB, gostDB *gorm.DB) ([]string, error) {
	cves := []string{}

	ovalCves, err := getAllCvesInOVAL(os, release, ovalDB)
	if err != nil {
		return nil, fmt.Errorf("failed to getAllCvesInOVAL: %w", err)
	}
	cves = append(cves, ovalCves...)

	gostCves, err := getAllCvesInGost(os, release, gostDB)
	if err != nil {
		return nil, fmt.Errorf("failed to getAllCvesInGost: %w", err)
	}
	cves = append(cves, gostCves...)

	uniqCves := []string{}
	m := map[string]struct{}{}
	for _, cveID := range cves {
		if _, ok := m[cveID]; !ok {
			m[cveID] = struct{}{}
			uniqCves = append(uniqCves, cveID)
		}
	}

	return uniqCves, nil
}

func getPackagebyCVEID(os, release, arch string, cveIDs []string, ovalDB, gostDB *gorm.DB) (map[string]map[string][]string, error) {
	ovalPkgs, err := getPackagebyCVEIDsInOVAL(os, release, arch, cveIDs, ovalDB)
	if err != nil {
		return nil, fmt.Errorf("failed to getPackagebyCVEIDInOVAL: %w", err)
	}

	gostPkgs, err := getPackagebyCVEIDsInGost(os, release, cveIDs, gostDB)
	if err != nil {
		return nil, fmt.Errorf("failed to getAllCvesInGost: %w", err)
	}

	pkgs := ovalPkgs
	for cveID, pkgVersions := range gostPkgs {
		if _, ok := pkgs[cveID]; !ok {
			pkgs[cveID] = pkgVersions
		} else {
			for packName, versions := range pkgVersions {
				pkgs[cveID][packName] = append(pkgs[cveID][packName], versions...)
			}
		}
	}

	return pkgs, nil
}

func getPackageMinVersion(os string, pkgs map[string]map[string][]string) (map[string]string, error) {
	pkgMinVersion := map[string]string{}
	for cveID, pkgVersions := range pkgs {
		if len(pkgVersions) == 0 {
			log.Logger.Debugw("Cannot reproduce the package that detects", "CVEID", cveID)
			continue
		}
		pkgName := util.RandomChoice(pkgVersions)
		versions := pkgVersions[pkgName]
		switch len(versions) {
		case 0:
			return nil, fmt.Errorf("failed to select min version: cveID: %s, pkgName: %s", cveID, pkgName)
		case 1:
			switch strings.ToLower(os) {
			case "debian", "ubuntu", "raspbian":
				v, err := debver.NewVersion(versions[0])
				if err != nil {
					return nil, fmt.Errorf("failed to debver.NewVersion(%s): %w", versions[0], err)
				}
				pkgMinVersion[pkgName] = v.String()
			case "redhat", "centos", "alma", "rocky", "oracle", "amazon":
				v := rpmver.NewVersion(versions[0])
				pkgMinVersion[pkgName] = v.String()
			case "alpine":
				v, err := apkver.NewVersion(versions[0])
				if err != nil {
					return nil, fmt.Errorf("failed to apkver.NewVersion(%s): %w", versions[0], err)
				}
				pkgMinVersion[pkgName] = string(v)
			default:
				return nil, fmt.Errorf("not supported os: %s", os)
			}
		case 2:
			switch strings.ToLower(os) {
			case "debian", "ubuntu", "raspbian":
				va, err := debver.NewVersion(versions[0])
				if err != nil {
					return nil, fmt.Errorf("failed to debver.NewVersion(%s): %w", versions[0], err)
				}
				vb, err := debver.NewVersion(versions[1])
				if err != nil {
					return nil, fmt.Errorf("failed to debver.NewVersion(%s): %w", versions[1], err)
				}
				if va.LessThan(vb) {
					log.Logger.Warnw("Different versions are presented in OVAL and Gost", "versions", versions)
					pkgMinVersion[pkgName] = va.String()

				} else {
					pkgMinVersion[pkgName] = vb.String()
				}
			case "redhat", "centos", "alma", "rocky", "oracle", "amazon":
				va := rpmver.NewVersion(versions[0])
				vb := rpmver.NewVersion(versions[1])
				if va.LessThan(vb) {
					log.Logger.Warnw("Different versions are presented in OVAL and Gost", "versions", versions)
					pkgMinVersion[pkgName] = va.String()
				} else {
					pkgMinVersion[pkgName] = vb.String()
				}
			case "alpine":
				va, err := apkver.NewVersion(versions[0])
				if err != nil {
					return nil, fmt.Errorf("failed to apkver.NewVersion(%s): %w", versions[0], err)
				}
				vb, err := apkver.NewVersion(versions[1])
				if err != nil {
					return nil, fmt.Errorf("failed to apkver.NewVersion(%s): %w", versions[1], err)
				}
				if va.LessThan(vb) {
					log.Logger.Warnw("Different versions are presented in OVAL and Gost", "versions", versions)
					pkgMinVersion[pkgName] = string(va)
				} else {
					pkgMinVersion[pkgName] = string(vb)
				}
			default:
				return nil, fmt.Errorf("not supported os: %s", os)
			}
		default:
			return nil, fmt.Errorf("failed to select min version: overflow versions length, actual: %d", len(versions))
		}
	}

	return pkgMinVersion, nil
}

func convertOneVersionSmaller(os string, pkgs map[string]string) (map[string]string, error) {
	m := map[string]string{}
	for pkgName, version := range pkgs {
		if strings.HasPrefix(version, TmpVer) {
			m[pkgName] = version
			continue
		}

		v, err := generateOneSmallerVersion(os, version)
		if err != nil {
			return nil, fmt.Errorf("failed to generateOneSmallerVersion: %w", err)
		}
		m[pkgName] = v
	}
	return m, nil
}

func generateOneSmallerVersion(os, version string) (string, error) {
	runes := []rune(version)
	for i := len(runes) - 1; i > 0; i = i - 1 {
		if 0x30 < runes[i] && runes[i] <= 0x39 {
			runes[i] = runes[i] - 1
			break
		}
	}
	genver := string(runes)

	switch strings.ToLower(os) {
	case "debian", "ubuntu", "raspbian":
		va, err := debver.NewVersion(version)
		if err != nil {
			return "", fmt.Errorf("failed to debver.NewVersion(%s): %w", version, err)
		}
		vb, err := debver.NewVersion(genver)
		if err != nil {
			return "", fmt.Errorf("failed to debver.NewVersion(%s): %w", genver, err)
		}
		if !vb.LessThan(va) {
			return "", fmt.Errorf("failed to generate smaller version: source version: %s generate version: %s", version, genver)
		}
	case "redhat", "centos", "alma", "rocky", "oracle", "amazon":
		va := rpmver.NewVersion(version)
		vb := rpmver.NewVersion(genver)
		if !vb.LessThan(va) {
			return "", fmt.Errorf("failed to generate smaller version: source version: %s generate version: %s", version, genver)
		}
	case "alpine":
		va, err := apkver.NewVersion(version)
		if err != nil {
			return "", fmt.Errorf("failed to apkver.NewVersion(%s): %w", version, err)
		}
		vb, err := apkver.NewVersion(genver)
		if err != nil {
			return "", fmt.Errorf("failed to apkver.NewVersion(%s): %w", genver, err)
		}
		if !vb.LessThan(va) {
			return "", fmt.Errorf("failed to generate smaller version: source version: %s generate version: %s", version, genver)
		}
	default:
		return "", fmt.Errorf("not supported os: %s", os)
	}

	return genver, nil
}

func convertToVulsPackages(os string, pkgs map[string]string) (map[string]vulsmodels.Package, error) {
	vulsPkgs := map[string]vulsmodels.Package{}
	for pkgName, version := range pkgs {
		p := vulsmodels.Package{
			Name: pkgName,
		}

		switch strings.ToLower(os) {
		case "debian", "ubuntu", "raspbian", "alpine":
			p.Version = version
		case "redhat", "centos", "alma", "rocky", "oracle", "amazon":
			ss := strings.Split(version, "-")
			if len(ss) != 2 {
				return nil, fmt.Errorf("invalid version format: version: %s", version)
			}
			p.Version = ss[0]
			p.Release = ss[1]
		default:
			return nil, fmt.Errorf("not supported os: %s", os)
		}
		vulsPkgs[pkgName] = p
	}
	return vulsPkgs, nil
}
