package generator

import (
	"errors"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/MaineK00n/vtgen/pkg/config"
	"github.com/MaineK00n/vtgen/pkg/generator/log"
	"github.com/MaineK00n/vtgen/pkg/generator/ospkg"
	"github.com/MaineK00n/vtgen/pkg/generator/util"
	vulsmodels "github.com/future-architect/vuls/models"
)

func Generate(configPath, outputRootDir string) error {
	if err := log.SetLogger(); err != nil {
		return fmt.Errorf("failed to SetLogger: %w", err)
	}

	log.Logger.Infow("generate vuls test files", "config path", configPath)
	cnf := config.TomlConfig{}
	if _, err := toml.DecodeFile(configPath, &cnf); err != nil {
		return fmt.Errorf("failed to decode config.toml: %w", err)
	}

	results := []vulsmodels.ScanResult{}
	scannedAt := time.Now()
	for _, target := range cnf.Generate.Target {
		switch target {
		case "ospkg":
			for serverName, ospkgCnf := range cnf.OSPkg {
				log.Logger.Infow("start GenOSPkg", "serverName", serverName)
				result, err := ospkg.GenOSPkg(ospkgCnf, cnf.Source.Oval, cnf.Source.Gost)
				if err != nil {
					return fmt.Errorf("failed to GenOSPkg: %w", err)
				}
				result.ServerName = serverName
				result.ScannedAt = scannedAt
				results = append(results, result)
			}
		case "library":
			return errors.New("not implemented error")
		case "cpeuri":
			return errors.New("not implemented error")
		default:
			return errors.New("not supported target")
		}
	}

	outputDir := path.Join(outputRootDir, scannedAt.Format(time.RFC3339))
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return fmt.Errorf("failed to create dir: %w", err)
	}
	for _, result := range results {
		if err := util.OutputResult(result, outputDir); err != nil {
			return fmt.Errorf("failed to OutputResult: %w", err)
		}
	}

	return nil
}
