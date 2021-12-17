package main

import (
	"fmt"
	"os"
	"time"

	"github.com/criteo/log4j-jndi-detector/internal/detector"
)

func main() {

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

	endTime := time.Now().UTC()

	hostAssessment := detector.HostAssessment{
		Hostname:                    name,
		ApplicationAssessments:      applicationAssessments,
		ApplicationAssessmentErrors: applicationAssessmentErrors,
		StartTime:                   startTime,
		EndTime:                     endTime,
	}

	fmt.Println(hostAssessment)
}
