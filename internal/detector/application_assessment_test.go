package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApplicationAssessmentToReport(t *testing.T) {
	applicationAssessment := ApplicationAssessment{
		Application:    ExampleApplication,
		JarAssessments: []JarAssessement{VulnerableJarAssessment, NonVulnerableJarAssessment},
	}

	report := applicationAssessment.ToReport()
	assert.Equal(t, map[string]interface{}{
		"appname":        "java -jar app.jar",
		"has_jndi_class": true,
		"kind":           "application",
		"nb_jars":        2,
		"nb_vuln_jars":   1,
		"pid":            int32(4567),
		"username":       "myuser",
		"versions":       "2.3.0",
		"vuln_jars":      []string{"app-vuln.jar"},
		"workingdir":     "/home/myuser",
	}, report)
}
