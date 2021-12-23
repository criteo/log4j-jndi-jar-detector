package detector

import "github.com/sirupsen/logrus"

type StdoutReporter struct{}

func (sr *StdoutReporter) ReportAssessment(hostAssessment HostAssessment) error {
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

func (sr *StdoutReporter) ReportError(fqdn string, anError error) error {
	logrus.Errorf(anError.Error())
	return nil
}
