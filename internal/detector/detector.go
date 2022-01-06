package detector

import (
	"fmt"
	"strings"
	"time"

	"github.com/Showmax/go-fqdn"
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

func runDetectionOneIteration(reporter Reporter, fqdn string) {
	applications, err := ListApplications("java")
	if err != nil {
		reporter.ReportError(fqdn, fmt.Errorf("unable to list java applications: %w", err))
		return
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
		FQDN:                        fqdn,
		ApplicationAssessments:      applicationAssessments,
		ApplicationAssessmentErrors: applicationAssessmentErrors,
		StartTime:                   startTime,
		EndTime:                     endTime,
	}

	if err := reporter.ReportAssessment(hostAssessment); err != nil {
		logrus.Errorf("unable to report host assessment: %s", err)
	}
}

func RunDetection(reporterArgs []string, daemon bool, daemonInterval time.Duration) {
	// check if provided reporters are valid
	for _, r := range reporterArgs {
		if !stringInSlice(r, AvailableReporters) {
			logrus.Panicf("reporters must belong to [%s]", strings.Join(AvailableReporters, ", "))
		}
	}

	reporter, err := NewReporterComposite(reporterArgs)
	if err != nil {
		logrus.Errorf("unable to create reporter: %s", err)
	}

	name, err := fqdn.FqdnHostname()
	if err != nil {
		logrus.Errorf("unable to get fqdn: %s", err)
		return
	}

	logrus.Infof("assessing host %s", name)

	for {
		runDetectionOneIteration(reporter, name)

		if !daemon {
			break
		} else {
			logrus.Infof("sleeping for %d seconds...", int(daemonInterval.Seconds()))
			time.Sleep(daemonInterval)
		}
	}
}
