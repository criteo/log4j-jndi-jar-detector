package detector

import (
	"fmt"
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

func TestSemverEqual(t *testing.T) {
	testCases := []struct {
		s1    Semver
		s2    Semver
		equal bool
	}{
		{Semver{2, 17, 5}, Semver{2, 17, 4}, false},
		{Semver{2, 17, 5}, Semver{2, 17, 5}, true},
		{Semver{2, 17, 5}, Semver{2, 17, 6}, false},
		{Semver{2, 17, 5}, Semver{2, 16, 5}, false},
		{Semver{2, 17, 5}, Semver{2, 18, 5}, false},
		{Semver{2, 17, 5}, Semver{1, 17, 5}, false},
		{Semver{2, 17, 5}, Semver{3, 17, 5}, false},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s < %s", tc.s1, tc.s2), func(t *testing.T) {
			assert.Equal(t, tc.equal, tc.s1.Equal(tc.s2))
		})
	}
}

func TestSemverLess(t *testing.T) {
	testCases := []struct {
		s1   Semver
		s2   Semver
		less bool
	}{
		{Semver{2, 17, 5}, Semver{2, 17, 4}, false},
		{Semver{2, 17, 5}, Semver{2, 17, 5}, false},
		{Semver{2, 17, 5}, Semver{2, 17, 6}, true},

		{Semver{2, 17, 5}, Semver{2, 16, 4}, false},
		{Semver{2, 17, 5}, Semver{2, 16, 5}, false},
		{Semver{2, 17, 5}, Semver{2, 16, 6}, false},

		{Semver{2, 17, 5}, Semver{2, 18, 4}, true},
		{Semver{2, 17, 5}, Semver{2, 18, 5}, true},
		{Semver{2, 17, 5}, Semver{2, 18, 6}, true},

		{Semver{2, 17, 5}, Semver{1, 16, 4}, false},
		{Semver{2, 17, 5}, Semver{1, 16, 5}, false},
		{Semver{2, 17, 5}, Semver{1, 16, 6}, false},
		{Semver{2, 17, 5}, Semver{1, 17, 4}, false},
		{Semver{2, 17, 5}, Semver{1, 17, 5}, false},
		{Semver{2, 17, 5}, Semver{1, 17, 6}, false},
		{Semver{2, 17, 5}, Semver{1, 18, 4}, false},
		{Semver{2, 17, 5}, Semver{1, 18, 5}, false},
		{Semver{2, 17, 5}, Semver{1, 18, 6}, false},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s < %s", tc.s1, tc.s2), func(t *testing.T) {
			assert.Equal(t, tc.less, tc.s1.Less(tc.s2))
		})
	}
}
