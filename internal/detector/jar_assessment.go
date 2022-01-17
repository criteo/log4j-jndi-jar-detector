package detector

type JarAssessement struct {
	Path                string
	isJNDIClassIncluded bool
	Log4jVersion        Semver
}

func (ja JarAssessement) IsVulnerable(safeVersion Semver) bool {
	if ja.Log4jVersion.Major < 2 {
		return false
	} else if ja.Log4jVersion.Major == 2 && ja.Log4jVersion.Minor >= 1 && !ja.isJNDIClassIncluded {
		return false
	} else if safeVersion.Less(ja.Log4jVersion) || safeVersion.Equal(ja.Log4jVersion) {
		return false
	}
	return true
}
