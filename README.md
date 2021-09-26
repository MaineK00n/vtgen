# vtgen
vtgen: Vuls Test file GENerator

# Installation and Usage
```console
$ git clone https://github.com/MaineK00n/vtgen
$ cd vtgen
$ make install
```

# vtgen help
```console
$ vtgen help
vuls test JSON generator

Usage:
  vtgen [command]

Available Commands:
  completion  generate the autocompletion script for the specified shell
  generate    generate json
  help        Help about any command
  version     Show version

Flags:
      --config string       /path/to/config.toml (default "$PWD/config.toml")
      --debug               debug mode
  -h, --help                help for vtgen
      --output-dir string   output file dir (default "$PWD/results")

Use "vtgen [command] --help" for more information about a command.
```

## vtgen generate and vuls report
```console
$ cp config.toml.template config.toml
$ vtgen generate
$ ls results/
2021-09-27T00:02:15+09:00
$ vuls report -config config.toml -results-dir (pwd)/results 2021-09-27T00:27:25+09:00
```

# License
MIT

# Author
MaineK00n([@MaineK00n](https://twitter.com/MaineK00n))