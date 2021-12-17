package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApplicationAssessmentErrorToReport(t *testing.T) {
	aae := ApplicationAssessmentError{
		Application: Application{
			Name:     "test-app",
			Username: "myuser",
			Cmdline:  "java -jar test.jar",
			Cwd:      "/home/myuser",
			Pid:      3456,
			Jars:     []string{"/home/myuser/test.jar"},
		},
		Message: "fatal error",
	}

	assert.Equal(t, aae.ToReport(), map[string]interface{}{
		"appname":    "java -jar test.jar",
		"kind":       "application_assessment_error",
		"message":    "fatal error",
		"username":   "myuser",
		"workingdir": "/home/myuser",
	})
}
