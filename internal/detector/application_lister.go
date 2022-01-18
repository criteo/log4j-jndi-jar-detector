package detector

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/shirou/gopsutil/process"
	"github.com/sirupsen/logrus"
)

const JAVA_AGENT_FLAG = "-javaagent:"

type Application struct {
	Name         string
	Username     string
	CmdlineSlice []string
	Cwd          string
	Pid          int32
	Jars         []string
}

func extractAgent(cmdlineSlice []string) ([]string, error) {
	paths := make([]string, 0)

	for _, arg := range cmdlineSlice {
		if strings.HasPrefix(arg, JAVA_AGENT_FLAG) {
			value := arg[len(JAVA_AGENT_FLAG):]
			kv := strings.Split(value, "=")
			if len(kv) < 1 || kv[0] == "" {
				return nil, fmt.Errorf("unable to parse javaagent %s", value)
			}
			paths = append(paths, kv[0])
		}
	}
	return paths, nil
}

func extractOptionArgs(cmdlineSlice []string, flags []string) ([]string, error) {
	flagIndices := make(map[int]struct{})

	for i, arg := range cmdlineSlice {
		for _, flag := range flags {
			if arg == flag {
				flagIndices[i+1] = struct{}{}
			}
		}
	}

	values := make(map[string]struct{})
	for idx := range flagIndices {
		if len(cmdlineSlice) <= idx {
			return nil, fmt.Errorf("unable to parse flag at position %d in %s", idx+1, strings.Join(cmdlineSlice, " "))
		}
		// In Windows, quotes wrapping arguments are not trimmed by the OS as in Unix
		flagValue := strings.Trim(cmdlineSlice[idx], "\"")
		values[flagValue] = struct{}{}
	}

	out := make([]string, 0)
	for v := range values {
		out = append(out, v)
	}
	return out, nil
}

func parseClassPathWithSeparators(classpath string) []string {
	var separator string
	switch runtime.GOOS {
	case "windows":
		separator = ";"
	default:
		separator = ":"
	}
	return strings.Split(classpath, separator)
}

func parseEnvVars(environ []string) (map[string]string, error) {
	envVars := make(map[string]string)
	for _, env := range environ {
		kv := strings.Split(env, "=")
		if len(kv) == 1 {
			envVars[kv[0]] = ""
		} else if len(kv) > 1 {
			envVars[kv[0]] = strings.Join(kv[1:], "=")
		} else {
			return nil, fmt.Errorf("unable to parse env variable %s", env)
		}
	}
	return envVars, nil
}

func extractClasspathsFromEnv(environ []string) ([]string, error) {
	envVars, err := parseEnvVars(environ)
	if err != nil {
		return nil, fmt.Errorf("unable to parse environment variables: %w", err)
	}

	jars := make([]string, 0)
	classpathEnvDetected := false

	for envKey, envValue := range envVars {
		if strings.Contains(envKey, "CLASSPATH") {
			logrus.Debugf("Classpath environment variable detected: %s=%s", envKey, envValue)
			jars = append(jars, parseClassPathWithSeparators(envValue)...)
			classpathEnvDetected = true
		}
	}

	if !classpathEnvDetected {
		logrus.Debugf("No classpath environment variable detected")
	}
	return jars, nil
}

func extractClasspathsFromProcess(cmdlineSlice []string, environ []string) ([]string, error) {
	jarRepository := make(map[string]struct{})
	agentJars, err := extractAgent(cmdlineSlice)
	if err != nil {
		return nil, fmt.Errorf("unable to parse javaagent from command line: %w", err)
	}
	for _, jar := range agentJars {
		jarRepository[jar] = struct{}{}
	}

	// Some jars or directories are referenced in command line flags
	cmdClasspaths, err := extractOptionArgs(cmdlineSlice, []string{"-jar", "-cp", "-classpath"})
	if err != nil {
		return nil, fmt.Errorf("unable to parse classpath from command line: %w", err)
	}

	for _, cmdClasspath := range cmdClasspaths {
		jarPaths := parseClassPathWithSeparators(cmdClasspath)
		for _, jar := range jarPaths {
			jarRepository[jar] = struct{}{}
		}
	}

	envClasspaths, err := extractClasspathsFromEnv(environ)
	if err != nil {
		return nil, fmt.Errorf("unable to parse classpath from env variables: %w", err)
	}

	for _, envCp := range envClasspaths {
		jarRepository[envCp] = struct{}{}
	}

	classpaths := make([]string, 0)
	for j := range jarRepository {
		classpaths = append(classpaths, j)
	}

	return classpaths, nil
}

func isDirectory(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	return fileInfo.IsDir(), err
}

func expandJarPaths(cwd string, paths []string) ([]string, error) {
	jars := []string{}
	for _, p := range paths {
		logrus.Debugf("trying to expand path %s", p)
		p = strings.TrimSuffix(p, "*")

		var absPath = p
		if !filepath.IsAbs(p) {
			absPath = filepath.Join(cwd, p)
		}

		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			continue
		}

		isDir, err := isDirectory(absPath)
		if err != nil {
			return nil, fmt.Errorf("unable to determine if %s is a directory: %w", absPath, err)
		}

		if isDir {
			logrus.Debugf("%s is a directory that needs to be expanded", p)
			files, err := ioutil.ReadDir(absPath)
			if err != nil {
				return nil, err
			}

			for _, file := range files {
				if filepath.Ext(file.Name()) == ".jar" && !file.IsDir() {
					absPath := filepath.Join(absPath, file.Name())
					logrus.Debugf("%s has been found", absPath)
					jars = append(jars, absPath)
				}
			}
		} else {
			// skip if it's not a jar
			if filepath.Ext(absPath) != ".jar" {
				continue
			}
			logrus.Debugf("%s is a jar and does not need to be expanded", p)
			jars = append(jars, absPath)
		}
	}
	return jars, nil
}

func ListApplications(commandPattern string) ([]Application, error) {
	processes, _ := process.Processes()
	applications := make([]Application, 0)
	for _, p := range processes {
		name, err := p.Name()
		if err != nil {
			continue
		}
		if !strings.HasPrefix(name, commandPattern) {
			logrus.Debugf("process with name %s will not be assessed", name)
			continue
		}

		pid, err := p.Ppid()
		if err != nil {
			logrus.Warnf("unable to extract pid from process: %s", err)
			continue
		}
		cmdlineSlice, err := p.CmdlineSlice()
		if err != nil {
			logrus.Warnf("unable to extract command line from process: %s", err)
			continue
		}
		logrus.Debugf("command line of process %d (%s) to assess: %s", pid, name, strings.Join(cmdlineSlice, " "))

		env, err := p.Environ()
		if err != nil {
			logrus.Warnf("unable to extract environ from process: %s", err)
			continue
		}

		classpaths, err := extractClasspathsFromProcess(cmdlineSlice, env)
		if err != nil {
			logrus.Warnf("unable to extract classpaths from process: %s", err)
			continue
		}

		cwd, err := p.Cwd()
		if err != nil {
			logrus.Warnf("unable to extract working dir from process: %s", err)
			continue
		}

		jarPaths, err := expandJarPaths(cwd, classpaths)
		if err != nil {
			logrus.Warnf("unable to expand classpaths: %s", err)
			continue
		}

		username, err := p.Username()
		if err != nil {
			logrus.Warnf("unable to extract username from process: %s", err)
			continue
		}

		applications = append(applications, Application{
			Name:         name,
			CmdlineSlice: cmdlineSlice,
			Cwd:          cwd,
			Pid:          p.Pid,
			Jars:         jarPaths,
			Username:     username,
		})
	}
	return applications, nil
}
