package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSemverParsing(t *testing.T) {
	semver1, err := ParseSemver("1.0.0")
	assert.NoError(t, err)
	assert.Equal(t, semver1, Semver{Major: 1, Minor: 0, Patch: 0})

	semver2, err := ParseSemver("2.6.5")
	assert.NoError(t, err)
	assert.Equal(t, semver2, Semver{Major: 2, Minor: 6, Patch: 5})

	semver3, err := ParseSemver("2.6")
	assert.NoError(t, err)
	assert.Equal(t, semver3, Semver{Major: 2, Minor: 6, Patch: 0})

	semver4, err := ParseSemver("2")
	assert.NoError(t, err)
	assert.Equal(t, semver4, Semver{Major: 2, Minor: 0, Patch: 0})

	semver5, err := ParseSemver("2.3.5.6")
	assert.NoError(t, err)
	assert.Equal(t, semver5, Semver{Major: 2, Minor: 3, Patch: 5})

	_, err = ParseSemver("abc")
	assert.Error(t, err)
}

func TestSemverToString(t *testing.T) {
	assert.Equal(t, "1.2.3", Semver{Major: 1, Minor: 2, Patch: 3}.String())
}
