package detector

import (
	"path"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func getCurrentPath() string {
	_, filename, _, _ := runtime.Caller(1)

	return path.Dir(filename)
}

func TestJarAssessorOnVulnerableLog4j(t *testing.T) {
	jarAssessor := NewJarAssessor(NewJarCheckerImpl())

	assessment, err := jarAssessor.Assess(filepath.Join(getCurrentPath(), "../..", "resources", "log4j-core-2.12.1.jar"))
	assert.NoError(t, err)
	assert.True(t, assessment.ContainsLog4j())
	assert.Equal(t, true, assessment.isJNDIClassIncluded)
	assert.Equal(t, Semver{2, 12, 1}, assessment.Log4jVersion)
	assert.Equal(t, true, assessment.IsVulnerable(Semver{2, 17, 0}))
}

func TestJarAssessorOnNonVulnerableLog4j(t *testing.T) {
	jarAssessor := NewJarAssessor(NewJarCheckerImpl())

	assessment1, err := jarAssessor.Assess(filepath.Join(getCurrentPath(), "../..", "resources", "log4j-core-2.17.0.jar"))
	assert.NoError(t, err)
	assert.True(t, assessment1.ContainsLog4j())
	assert.Equal(t, false, assessment1.isJNDIClassIncluded)
	assert.Equal(t, Semver{2, 17, 0}, assessment1.Log4jVersion)
	assert.Equal(t, false, assessment1.IsVulnerable(Semver{2, 17, 0}))

	assessment2, err := jarAssessor.Assess(filepath.Join(getCurrentPath(), "../..", "resources", "log4j-jcl-2.13.2.jar"))
	assert.NoError(t, err)
	assert.False(t, assessment2.ContainsLog4j())
}
