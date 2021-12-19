package detector

import (
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

var AvailableReporters = []string{
	"stdout",
	"elasticsearch",
}

func stringInSlice(str string, slice []string) bool {
	for _, s := range slice {
		if str == s {
			return true
		}
	}
	return false
}

func runDetectionOneIteration(reporters []string) {
	name, err := os.Hostname()
	if err != nil {
		logrus.Errorf("unable to get hostname: %s", err)
		return
	}

	applications, err := ListJavaApplications("java")
	if err != nil {
		logrus.Errorf("unable to list java applications: %s", err)
	}

	applicationAssessor := NewApplicationAssessor(NewJarCheckerImpl())
	applicationAssessments := make([]ApplicationAssessment, 0)
	applicationAssessmentErrors := make([]ApplicationAssessmentError, 0)

	startTime := time.Now().UTC()

	logrus.Info("===> assessment started <===")

	for _, application := range applications {
		applicationAssessment, err := applicationAssessor.Assess(application)
		if err != nil {
			applicationAssessmentErrors = append(applicationAssessmentErrors, ApplicationAssessmentError{
				Application: application,
				Message:     err.Error(),
			})
		} else {
			applicationAssessments = append(applicationAssessments, applicationAssessment)
		}
	}

	logrus.Info("===> assessment done <===")

	endTime := time.Now().UTC()

	hostAssessment := HostAssessment{
		Hostname:                    name,
		ApplicationAssessments:      applicationAssessments,
		ApplicationAssessmentErrors: applicationAssessmentErrors,
		StartTime:                   startTime,
		EndTime:                     endTime,
	}

	if stringInSlice("stdout", reporters) {
		logrus.Info("reporting on standard output")
		stdoutReporter := StdoutReporter{}
		stdoutReporter.Report(hostAssessment)
	}

	if stringInSlice("elasticsearch", reporters) {
		esURL := os.Getenv("ES_URL")
		esUsername := os.Getenv("ES_USERNAME")
		esPassword := os.Getenv("ES_PASSWORD")
		esIndex := os.Getenv("ES_INDEX")

		logrus.Infof("reporting to elasticsearch %s", esURL)
		reporter, err := NewElasticSearchReporter(esURL, esUsername, esPassword, esIndex)
		if err != nil {
			logrus.Errorf("unable to create elasticsearch reporter: %s", err)
			return
		}

		err = reporter.Report(hostAssessment)
		if err != nil {
			logrus.Errorf("unable to report assessment to elasticsearch: %s", err)
			return
		}
	}
}

func RunDetection(reporters []string, Daemon bool, DaemonInterval time.Duration) {
	// check if provided reporters are valid
	for _, r := range reporters {
		if !stringInSlice(r, AvailableReporters) {
			logrus.Panicf("reporters must belong to [%s]", strings.Join(AvailableReporters, ", "))
		}
	}

	// check if env variable for elasticsearch reporter are provided
	if stringInSlice("elasticsearch", reporters) {
		esURL := os.Getenv("ES_URL")
		esUsername := os.Getenv("ES_USERNAME")
		esPassword := os.Getenv("ES_PASSWORD")
		esIndex := os.Getenv("ES_INDEX")

		if esURL == "" {
			logrus.Panic("provide ES_URL environment variable")
		}

		if esUsername == "" {
			logrus.Panic("provide ES_USERNAME environment variable")
		}

		if esPassword == "" {
			logrus.Panic("provide ES_PASSWORD environment variable")
		}

		if esIndex == "" {
			logrus.Panic("provide ES_INDEX environment variable")
		}
	}

	for {
		runDetectionOneIteration(reporters)

		if !Daemon {
			break
		} else {
			logrus.Infof("sleeping for %d seconds...", int(DaemonInterval.Seconds()))
			time.Sleep(DaemonInterval)
		}
	}
}
