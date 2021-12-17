package detector

type JarAssessement struct {
	Path                string
	isJNDIClassIncluded bool
	Log4jVersion        Semver
}

func (ja JarAssessement) IsVulnerable() bool {
	if ja.Log4jVersion.Major < 2 {
		return false
	} else if ja.Log4jVersion.Major == 2 && ja.Log4jVersion.Minor == 0 {
		return false
	} else if ja.Log4jVersion.Major == 2 && ja.Log4jVersion.Minor >= 16 {
		return false
	} else if ja.Log4jVersion.Major == 2 && ja.Log4jVersion.Minor >= 1 && !ja.isJNDIClassIncluded {
		return false
	}
	return true
}
