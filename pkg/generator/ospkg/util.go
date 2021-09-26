package ospkg

import (
	"fmt"
	"math"
	"strings"
)

func major(osVer string) (majorVersion string) {
	return strings.Split(osVer, ".")[0]
}

func majorDotMinor(osVer string) (majorMinorVersion string) {
	ss := strings.Split(osVer, ".")
	if len(ss) < 3 {
		return osVer
	}
	return strings.Join(ss[:2], ".")
}

// getAmazonLinux2 returns AmazonLinux1 or 2
func getAmazonLinux1or2(osVersion string) string {
	ss := strings.Fields(osVersion)
	if ss[0] == "2" {
		return "2"
	}
	return "1"
}

var TmpVer = fmt.Sprintf("%d:0.vtgen-0", math.MaxUint8)
