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

	testCases := []struct {
		Jar               string
		Version           Semver
		JNDIClassIncluded bool
		IsVulnerable      bool
	}{
		{"log4j-core-2.12.1.jar", Semver{2, 12, 1}, true, true},
		{"log4j-core-2.17.0.jar", Semver{2, 17, 0}, false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.Jar, func(t *testing.T) {
			assessment, err := jarAssessor.Assess(filepath.Join(getCurrentPath(), "../..", "resources", tc.Jar))
			assert.NoError(t, err)
			assert.Equal(t, tc.JNDIClassIncluded, assessment.isJNDIClassIncluded)
			assert.Equal(t, tc.Version, assessment.Log4jVersion)
			assert.Equal(t, tc.IsVulnerable, assessment.IsVulnerable())
		})
	}
}
