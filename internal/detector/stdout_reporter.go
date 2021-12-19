package detector

import "github.com/sirupsen/logrus"

type StdoutReporter struct{}

func (sr *StdoutReporter) Report(hostAssessment HostAssessment) error {
	for _, a := range hostAssessment.ApplicationAssessments {
		for _, j := range a.JarAssessments {
			if !j.IsVulnerable() {
				continue
			}
			logrus.Infof("%s used in process %d is vulnerable (Version=%s, JNDIClassExists=%t)",
				j.Path, a.Application.Pid, j.Log4jVersion, j.isJNDIClassIncluded)
		}
	}
	return nil
}
