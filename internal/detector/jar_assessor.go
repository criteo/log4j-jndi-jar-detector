package detector

import (
	"archive/zip"
	"bufio"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

var regex = regexp.MustCompile("(.*)=(.*)")
var JarAssessmentCache = cache.New(3*time.Hour, 10*time.Minute)

const JNDIClassName = "JndiLookup.class"

type JarAssessor struct {
	jarChecker JarChecker
}

type JarAssessmentError struct {
	Message string
}

type JarChecker interface {
	IsVulnerable(path string) (bool, error)
}

type JarCheckerImpl struct {
	classToFind string
}

func NewJarCheckerImpl() *JarCheckerImpl {
	return &JarCheckerImpl{
		classToFind: JNDIClassName,
	}
}

func (jc *JarCheckerImpl) IsVulnerable(path string) (bool, error) {

	return false, nil
}

func NewJarAssessor(jarChecker JarChecker) JarAssessor {
	return JarAssessor{
		jarChecker: jarChecker,
	}
}

func (ja *JarAssessor) Assess(path string) (JarAssessement, error) {
	logrus.Infof("assessing: %s", path)

	if v, found := JarAssessmentCache.Get(path); found {
		return v.(JarAssessement), nil
	}

	read, err := zip.OpenReader(path)

	if err != nil {
		return JarAssessement{}, fmt.Errorf("unable to open zip file %s: %w", path, err)
	}
	defer read.Close()

	jniClassPresent := false

	for _, file := range read.File {
		if strings.Contains(file.Name, JNDIClassName) {
			jniClassPresent = true
		}
		if !strings.HasSuffix(file.Name, "pom.properties") {
			continue
		}

		freader, err := file.Open()
		if err != nil {
			return JarAssessement{}, fmt.Errorf("unable to open pom.properties from %s: %w", path, err)
		}
		defer freader.Close()

		scanner := bufio.NewScanner(freader)
		props := make(map[string]string)

		for scanner.Scan() {
			res := regex.FindStringSubmatch(scanner.Text())
			if len(res) < 3 {
				continue
			}

			props[res[1]] = res[2]
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}

		if artifact, ok := props["artifactId"]; ok && (artifact == "log4j" || artifact == "log4j-core") {
			if v, ok := props["version"]; ok {
				semver, err := ParseSemver(v)
				if err != nil {
					logrus.Warnf("unable to parse semver: %s", err)
				}
				jarAssessment := JarAssessement{
					Path:                path,
					isJNDIClassIncluded: jniClassPresent,
					Log4jVersion:        semver,
				}
				JarAssessmentCache.Set(path, jarAssessment, cache.DefaultExpiration)
				return jarAssessment, nil
			}
		}
	}
	return JarAssessement{}, nil
}
