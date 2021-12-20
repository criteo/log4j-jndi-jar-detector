package detector

import (
	"log"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractAgentNoKV(t *testing.T) {
	jars, err := extractAgent("java -javaagent:/path/to/elastic-apm-agent.jar -Delastic.apm.service_name=my-cool-service -javaagent:/path/to/elastic.jar -Delastic.apm.server_url=http://localhost:8200 -jar application.jar")
	assert.NoError(t, err)
	assert.ElementsMatch(t, jars, []string{"/path/to/elastic-apm-agent.jar", "/path/to/elastic.jar"})
}

func TestExtractAgentWithKV(t *testing.T) {
	jars, err := extractAgent("java -javaagent:/path/to/elastic-apm-agent.jar=test -Delastic.apm.service_name=my-cool-service -Delastic.apm.server_url=http://localhost:8200 -jar application.jar")
	assert.NoError(t, err)
	assert.ElementsMatch(t, jars, []string{"/path/to/elastic-apm-agent.jar"})
}

func TestExtractAgentWithEmptyFlag(t *testing.T) {
	_, err := extractAgent("java -javaagent: -Delastic.apm.service_name=my-cool-service -Delastic.apm.server_url=http://localhost:8200 -jar application.jar")
	assert.Error(t, err)
}

func TestExtractOptionArgsWithSomeArgs(t *testing.T) {
	jars, err := extractOptionArgs(
		"java -javaagent:/path/to/elastic-apm-agent.jar -cp app-cp.jar -classpath rel/app-classpath.jar -Delastic.apm.service_name=my-cool-service -javaagent:/path/to/elastic.jar "+
			"-Delastic.apm.server_url=http://localhost:8200 -jar application.jar", []string{"-classpath", "-jar", "-cp"})
	assert.NoError(t, err)
	assert.ElementsMatch(t, jars, []string{"application.jar", "app-cp.jar", "rel/app-classpath.jar"})
}

func TestExtractOptionArgsWithoutArgs(t *testing.T) {
	jars, err := extractOptionArgs(
		"java -javaagent:/path/to/elastic-apm-agent.jar -Delastic.apm.service_name=my-cool-service -javaagent:/path/to/elastic.jar "+
			"-Delastic.apm.server_url=http://localhost:8200", []string{"-classpath", "-jar", "-cp"})
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
	classpaths, err := extractClasspathsFromProcess("java -javaagent:/path/to/elastic-apm-agent.jar -cp test.jar -Delastic.apm.service_name=my-cool-service "+
		"-javaagent:/path/to/elastic.jar -Delastic.apm.server_url=http://localhost:8200 -jar application.jar", []string{"TEST=myvar", "CLASSPATH=cp.jar"})
	assert.NoError(t, err)
	assert.ElementsMatch(t, classpaths, []string{"/path/to/elastic-apm-agent.jar", "/path/to/elastic.jar", "test.jar", "application.jar", "cp.jar"})
}

func TestExpandJarPaths(t *testing.T) {
	var tmpDir = t.TempDir()
	f1, err := os.Create(path.Join(tmpDir, "temp.txt"))
	assert.NoError(t, err)
	defer f1.Close()

	f2, err := os.Create(path.Join(tmpDir, "temp.jar"))
	assert.NoError(t, err)
	defer f2.Close()

	err = os.Mkdir(path.Join(tmpDir, "subdir"), 0700)
	assert.NoError(t, err)

	f3, err := os.Create(path.Join(tmpDir, "subdir/temp.jar"))
	if err != nil {
		log.Fatal(err)
	}
	defer f3.Close()

	jars, err := expandJarPaths(tmpDir, []string{".", tmpDir})
	assert.NoError(t, err)
	assert.ElementsMatch(t, jars, []string{
		path.Join(tmpDir, "temp.jar"),
		path.Join(tmpDir, "subdir", "temp.jar"),
		path.Join(tmpDir, "temp.jar"),
		path.Join(tmpDir, "subdir", "temp.jar"),
	})
}
