package detector

import (
	"fmt"
	"strconv"
	"strings"
)

type Semver struct {
	Major int
	Minor int
	Patch int
}

func (s Semver) String() string {
	return fmt.Sprintf("%d.%d.%d", s.Major, s.Minor, s.Patch)
}

func ParseSemver(version string) (Semver, error) {
	values := strings.Split(version, ".")
	var major, minor, patch int
	if len(values) > 0 {
		v, err := strconv.ParseInt(values[0], 10, 32)
		if err != nil {
			return Semver{}, fmt.Errorf("cannot parse version %s", version)
		}
		major = int(v)
	}

	if len(values) > 1 {
		v, err := strconv.ParseInt(values[1], 10, 32)
		if err != nil {
			return Semver{}, fmt.Errorf("cannot parse version %s", version)
		}
		minor = int(v)
	}

	if len(values) > 2 {
		v, err := strconv.ParseInt(values[2], 10, 32)
		if err != nil {
			return Semver{}, fmt.Errorf("cannot parse version %s", version)
		}
		patch = int(v)
	}

	return Semver{Major: major, Minor: minor, Patch: patch}, nil
}
