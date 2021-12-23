package detector

import (
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractAgentNoKV(t *testing.T) {
	args := []string{
		"java",
		"-javaagent:/path/to/elastic-apm-agent.jar",
		"-Delastic.apm.service_name=my-cool-service",
		"-javaagent:/path/to/elastic.jar",
		"-Delastic.apm.server_url=http://localhost:8200",
		"-jar application.jar",
	}

	jars, err := extractAgent(args)
	assert.NoError(t, err)
	assert.ElementsMatch(t, jars, []string{"/path/to/elastic-apm-agent.jar", "/path/to/elastic.jar"})
}

func TestExtractAgentWithKV(t *testing.T) {
	args := []string{
		"java",
		"-javaagent:/path/to/elastic-apm-agent.jar=test",
		"-Delastic.apm.service_name=my-cool-service",
		"-Delastic.apm.server_url=http://localhost:8200",
		"-jar",
		"application.jar",
	}
	jars, err := extractAgent(args)
	assert.NoError(t, err)
	assert.ElementsMatch(t, jars, []string{"/path/to/elastic-apm-agent.jar"})
}

func TestExtractAgentWithEmptyFlag(t *testing.T) {
	args := []string{
		"java",
		"-javaagent:",
		"-Delastic.apm.service_name=my-cool-service",
		"-Delastic.apm.server_url=http://localhost:8200",
		"-jar",
		"application.jar",
	}
	_, err := extractAgent(args)
	assert.Error(t, err)
}

func TestExtractOptionArgsWithSomeArgs(t *testing.T) {
	args := []string{
		"java",
		"-javaagent:/path/to/elastic-apm-agent.jar",
		"-cp",
		"app-cp.jar",
		"-classpath",
		"rel/app-classpath.jar",
		"-Delastic.apm.service_name=my-cool-service",
		"-javaagent:/path/to/elastic.jar",
		"-Delastic.apm.server_url=http://localhost:8200",
		"-jar",
		"application.jar",
	}
	jars, err := extractOptionArgs(args, []string{"-classpath", "-jar", "-cp"})
	assert.NoError(t, err)
	assert.ElementsMatch(t, jars, []string{"application.jar", "app-cp.jar", "rel/app-classpath.jar"})
}

func TestExtractOptionArgsWithoutArgs(t *testing.T) {
	args := []string{
		"java",
		"-javaagent:/path/to/elastic-apm-agent.jar",
		"-Delastic.apm.service_name=my-cool-service",
		"-javaagent:/path/to/elastic.jar",
		"-Delastic.apm.server_url=http://localhost:8200",
	}
	jars, err := extractOptionArgs(
		args, []string{"-classpath", "-jar", "-cp"})
	assert.NoError(t, err)
	assert.ElementsMatch(t, jars, []string{})
}

func TestParseEnvVarsNominal(t *testing.T) {
	envVars, err := parseEnvVars([]string{
		"TEST=abc",
		"MYVAR=xyz",
	})
	assert.NoError(t, err)
	assert.Equal(t, envVars, map[string]string{
		"TEST":  "abc",
		"MYVAR": "xyz",
	})
}

func TestParseEnvVarsKeyOnly(t *testing.T) {
	envVars, err := parseEnvVars([]string{
		"TEST",
		"MYVAR=xyz",
	})
	assert.NoError(t, err)
	assert.Equal(t, envVars, map[string]string{
		"TEST":  "",
		"MYVAR": "xyz",
	})
}

func TestParseEnvVarsWithMultpleEqualSigns(t *testing.T) {
	envVars, err := parseEnvVars([]string{
		"TEST=ABC=ABNC",
		"MYVAR=xyz",
	})
	assert.NoError(t, err)
	assert.Equal(t, envVars, map[string]string{
		"TEST":  "ABC=ABNC",
		"MYVAR": "xyz",
	})
}

func TestExtractJarsFromProcess(t *testing.T) {
	args := []string{
		"java",
		"-javaagent:/path/to/elastic-apm-agent.jar",
		"-cp",
		"test.jar",
		"-Delastic.apm.service_name=my-cool-service",
		"-javaagent:/path/to/elastic.jar",
		"-Delastic.apm.server_url=http://localhost:8200",
		"-jar",
		"application.jar",
	}
	classpaths, err := extractClasspathsFromProcess(args, []string{
		"TEST=myvar",
		"CLASSPATH=cp.jar",
		"USER_CLASSPATH=user.jar:/usr/lib/*",
		"USER_CLASSPATH_TEST=user2.jar",
	})
	assert.NoError(t, err)
	assert.ElementsMatch(t, classpaths, []string{
		"/path/to/elastic-apm-agent.jar",
		"/path/to/elastic.jar", "test.jar",
		"application.jar",
		"cp.jar",
		"user.jar",
		"user2.jar",
		"/usr/lib/*",
	})
}

func TestExpandJarPaths(t *testing.T) {
	var tmpDir = t.TempDir()
	f1, err := os.Create(filepath.Join(tmpDir, "temp.txt"))
	assert.NoError(t, err)
	defer f1.Close()

	f2, err := os.Create(filepath.Join(tmpDir, "temp.jar"))
	assert.NoError(t, err)
	defer f2.Close()

	err = os.Mkdir(filepath.Join(tmpDir, "subdir"), 0700)
	assert.NoError(t, err)

	f3, err := os.Create(filepath.Join(tmpDir, "subdir/temp.jar"))
	if err != nil {
		log.Fatal(err)
	}
	defer f3.Close()

	jars, err := expandJarPaths(tmpDir, []string{".", filepath.Join(tmpDir, "subdir/*")})
	assert.NoError(t, err)
	assert.ElementsMatch(t, jars, []string{
		filepath.Join(tmpDir, "temp.jar"),
		filepath.Join(tmpDir, "subdir", "temp.jar"),
	})
}

func TestDoNotExpandNonJars(t *testing.T) {
	var tmpDir = t.TempDir()
	f1, err := os.Create(filepath.Join(tmpDir, "test.txt"))
	assert.NoError(t, err)
	defer f1.Close()

	jars, err := expandJarPaths(tmpDir, []string{"test.txt"})
	assert.NoError(t, err)
	assert.Len(t, jars, 0)
}

func TestPathsContainingStars(t *testing.T) {
	var tmpDir = t.TempDir()
	f1, err := os.Create(filepath.Join(tmpDir, "test.jar"))
	assert.NoError(t, err)
	defer f1.Close()

	jars, err := expandJarPaths(tmpDir, []string{filepath.Join(tmpDir, "*")})
	assert.NoError(t, err)
	assert.ElementsMatch(t, jars, []string{filepath.Join(tmpDir, "test.jar")})
}

func TestDirWithJarExtension(t *testing.T) {
	var tmpDir = t.TempDir()
	err := os.Mkdir(filepath.Join(tmpDir, "test.jar"), 0o755)
	assert.NoError(t, err)

	jars, err := expandJarPaths(tmpDir, []string{tmpDir})
	assert.NoError(t, err)
	assert.ElementsMatch(t, jars, []string{})
}

func TestDirWithJarsInNestedDirs(t *testing.T) {
	var tmpDir = t.TempDir()
	err := os.Mkdir(filepath.Join(tmpDir, "subdir1"), 0o755)
	assert.NoError(t, err)

	f1, err := os.Create(filepath.Join(tmpDir, "test.jar"))
	assert.NoError(t, err)
	defer f1.Close()

	f2, err := os.Create(filepath.Join(tmpDir, "subdir1", "user.jar"))
	assert.NoError(t, err)
	defer f2.Close()

	jars, err := expandJarPaths(tmpDir, []string{filepath.Join(tmpDir, "*")})
	assert.NoError(t, err)
	assert.ElementsMatch(t, jars, []string{filepath.Join(tmpDir, "test.jar")})

	jars2, err := expandJarPaths(tmpDir, []string{filepath.Join(tmpDir, "*"), filepath.Join(tmpDir, "subdir1", "*")})
	assert.NoError(t, err)
	assert.ElementsMatch(t, jars2, []string{filepath.Join(tmpDir, "test.jar"), filepath.Join(tmpDir, "subdir1", "user.jar")})
}
