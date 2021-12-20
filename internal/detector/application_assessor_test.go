package detector

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApplicationAssessment(t *testing.T) {
	assessor := NewApplicationAssessor(NewJarCheckerImpl())
	assessment, err := assessor.Assess(Application{
		Name:         "myapp",
		Username:     "myuser",
		CmdlineSlice: []string{"java", "-jar", "app.jar"},
		Cwd:          "/home/myuser",
		Pid:          4567,
		Jars: []string{
			filepath.Join(getCurrentPath(), "../..", "resources", "log4j-core-2.12.1.jar"),
			filepath.Join(getCurrentPath(), "../..", "resources", "log4j-core-2.17.0.jar"),
		},
	})
	assert.NoError(t, err)
	assert.Len(t, assessment.JarAssessments, 2)
}

func TestApplicationAssessmentUnexistingJar(t *testing.T) {
	assessor := NewApplicationAssessor(NewJarCheckerImpl())
	_, err := assessor.Assess(Application{
		Name:         "myapp",
		Username:     "myuser",
		CmdlineSlice: []string{"java", "-jar", "app.jar"},
		Cwd:          "/home/myuser",
		Pid:          4567,
		Jars: []string{
			"unexisting.jar",
		},
	})
	assert.Error(t, err)
}
