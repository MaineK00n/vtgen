package config

// Version of vtgen
var Version = "`make build` or `make install` will show the version"

// Revision of Git
var Revision string

// TomlConfig
type TomlConfig struct {
	Source   Source             `toml:"source"`
	Generate Generate           `toml:"generate"`
	OSPkg    map[string]OSPkg   `toml:"ospkg"`
	Library  map[string]Library `toml:"library"`
	CPEURI   map[string]CPEURI  `toml:"cpeuri"`
}

type Source struct {
	Cve  string `toml:"cve"`
	Oval string `toml:"oval"`
	Gost string `toml:"gost"`
}

type Generate struct {
	Target []string `toml:"target"`
}

type OSPkg struct {
	OS      string   `toml:"os"`
	Release string   `toml:"release"`
	Arch    string   `toml:"arch"`
	Mode    string   `toml:"mode"`
	Size    float64  `toml:"size"`
	Cves    []string `toml:"cves"`
}

type Library struct {
}

type CPEURI struct {
}
