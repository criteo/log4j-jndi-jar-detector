package main

import (
	"os"
	"time"

	"github.com/criteo/log4j-jndi-detector/internal/detector"
	"github.com/sirupsen/logrus"
)

func main() {
	esURL := os.Getenv("ES_URL")
	esUsername := os.Getenv("ES_USERNAME")
	esPassword := os.Getenv("ES_PASSWORD")
	esIndex := os.Getenv("ES_INDEX")

	if esURL == "" {
		logrus.Panic("Please provide ES_URL environment variable")
	}

	if esUsername == "" {
		logrus.Panic("Please provide ES_USERNAME environment variable")
	}

	if esPassword == "" {
		logrus.Panic("Please provide ES_PASSWORD environment variable")
	}

	if esIndex == "" {
		logrus.Panic("Please provide ES_INDEX environment variable")
	}

	name, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	applications, err := detector.ListJavaApplications("java")
	if err != nil {
		panic(err)
	}

	applicationAssessor := detector.NewApplicationAssessor(detector.NewJarCheckerImpl())
	applicationAssessments := make([]detector.ApplicationAssessment, 0)
	applicationAssessmentErrors := make([]detector.ApplicationAssessmentError, 0)

	startTime := time.Now().UTC()

	logrus.Info("Assessment started")

	for _, application := range applications {
		applicationAssessment, err := applicationAssessor.Assess(application)
		if err != nil {
			applicationAssessmentErrors = append(applicationAssessmentErrors, detector.ApplicationAssessmentError{
				Application: application,
				Message:     err.Error(),
			})
		} else {
			applicationAssessments = append(applicationAssessments, *applicationAssessment)
		}
	}

	logrus.Info("Assessment done")

	endTime := time.Now().UTC()

	hostAssessment := detector.HostAssessment{
		Hostname:                    name,
		ApplicationAssessments:      applicationAssessments,
		ApplicationAssessmentErrors: applicationAssessmentErrors,
		StartTime:                   startTime,
		EndTime:                     endTime,
	}

	stdoutReporter := detector.StdoutReporter{}
	stdoutReporter.Report(hostAssessment)

	reporter, err := detector.NewElasticSearchReporter(esURL, esUsername, esPassword, esIndex)
	if err != nil {
		logrus.Panic(err)
	}

	err = reporter.Report(hostAssessment)
	if err != nil {
		logrus.Panic(err)
	}
}
