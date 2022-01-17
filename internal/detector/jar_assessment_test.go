package detector

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJarAssessmentIsVulnerable(t *testing.T) {
	testCases := []struct {
		jndi       bool
		version    Semver
		vulnerable bool
	}{
		{false, Semver{1, 0, 0}, false},
		{true, Semver{1, 0, 0}, false},
		{false, Semver{2, 0, 0}, true},
		{true, Semver{2, 0, 0}, true},
		{true, Semver{2, 2, 0}, true},
		{false, Semver{2, 2, 0}, false},
		{false, Semver{2, 17, 0}, false},
		{true, Semver{2, 17, 0}, false},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("jndi=%t version=%s", tc.jndi, tc.version), func(t *testing.T) {
			ja := JarAssessement{
				isJNDIClassIncluded: tc.jndi,
				Path:                "/home/user/app.jar",
				Log4jVersion:        tc.version,
			}
			assert.Equal(t, tc.vulnerable, ja.IsVulnerable(Semver{2, 17, 0}))
		})
	}
}
