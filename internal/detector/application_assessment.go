package detector

import (
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

type ApplicationAssessment struct {
	Application    Application
	JarAssessments []JarAssessement
}

func (aa *ApplicationAssessment) IsVulnerable(safeVersion Semver) bool {
	for _, j := range aa.JarAssessments {
		if j.IsVulnerable(safeVersion) {
			return true
		}
	}
	return false
}

func (aa ApplicationAssessment) ToReport(safeVersion Semver) map[string]interface{} {
	vulnJars := make([]string, 0)
	hasJNDIClass := false
	versionSet := map[Semver]struct{}{}
	vulnerableAssessmentsCount := 0

	for _, j := range aa.JarAssessments {
		// skip non vulnerable assessments
		if !j.IsVulnerable(safeVersion) {
			continue
		}
		vulnerableAssessmentsCount += 1

		if j.isJNDIClassIncluded {
			hasJNDIClass = true
		}

		versionSet[j.Log4jVersion] = struct{}{}

		relPath, err := filepath.Rel(aa.Application.Cwd, j.Path)
		if err != nil {
			logrus.Warnf("unable to compute relative path of %s: %s", j.Path, err)
			relPath = j.Path
		}
		vulnJars = append(vulnJars, relPath)
	}

	versions := make([]string, 0)
	for v := range versionSet {
		versions = append(versions, v.String())
	}

	return map[string]interface{}{
		"kind":           "application",
		"appname":        strings.Join(aa.Application.CmdlineSlice, " "),
		"username":       aa.Application.Username,
		"workingdir":     aa.Application.Cwd,
		"pid":            aa.Application.Pid,
		"nb_vuln_jars":   vulnerableAssessmentsCount,
		"vuln_jars":      vulnJars,
		"nb_jars":        len(aa.JarAssessments),
		"has_jndi_class": hasJNDIClass,
		"versions":       strings.Join(versions, ","),
	}
}
