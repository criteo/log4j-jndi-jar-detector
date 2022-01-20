package detector

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var NonVulnerableJarAssessment = JarAssessement{
	isJNDIClassIncluded: false,
	Path:                "/home/myuser/app.jar",
	Log4jVersion:        Semver{Major: 2, Minor: 1, Patch: 0},
}

var VulnerableJarAssessment = JarAssessement{
	isJNDIClassIncluded: true,
	Path:                "/home/myuser/app-vuln.jar",
	Log4jVersion:        Semver{Major: 2, Minor: 3, Patch: 0},
}

var ExampleApplication = Application{
	Name:         "myapp",
	Username:     "myuser",
	CmdlineSlice: []string{"java", "-jar", "app.jar"},
	Cwd:          "/home/myuser",
	Pid:          4567,
	Jars:         []string{"app.jar"},
}

var VulnerableApplicationAssessment = ApplicationAssessment{
	Application:    ExampleApplication,
	JarAssessments: []JarAssessement{NonVulnerableJarAssessment, VulnerableJarAssessment},
}

var NonVulnerableApplicationAssessment = ApplicationAssessment{
	Application:    ExampleApplication,
	JarAssessments: []JarAssessement{NonVulnerableJarAssessment},
}

func TestHostAssessmentToReport(t *testing.T) {
	startTime := time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)
	endTime := time.Date(2021, 1, 1, 1, 2, 10, 0, time.UTC)

	ha := NewHostAssessment("test", []ApplicationAssessment{VulnerableApplicationAssessment, NonVulnerableApplicationAssessment},
		[]ApplicationAssessmentError{}, startTime, endTime)

	assert.Equal(t, map[string]interface{}{
		"duration":               130.0,
		"fqdn":                   "test",
		"kind":                   "host",
		"nb_java_processes":      2,
		"nb_vuln_java_processes": 1,
		"run_end_time":           "2021-01-01T01:02:10Z",
		"run_start_time":         "2021-01-01T01:00:00Z",
	}, ha.ToReport(Semver{Major: 2, Minor: 17, Patch: 0}))
}
