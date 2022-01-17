//go:generate mockgen -source reporter.go -destination ./reporter_mock.go -package detector

package detector

import (
	"fmt"
)

type Reporter interface {
	ReportAssessment(hostAssessment HostAssessment, safeVersion Semver) error
	ReportError(fqdn string, anError error) error
}

type ReporterComposite struct {
	reporters map[string]Reporter
}

func NewReporterComposite(reporterArgs []string) (*ReporterComposite, error) {
	reporterComposite := ReporterComposite{
		reporters: make(map[string]Reporter),
	}
	if stringInSlice("stdout", reporterArgs) {
		reporter := StdoutReporter{}
		reporterComposite.reporters["stdout"] = &reporter
	}

	if stringInSlice("elasticsearch", reporterArgs) {
		reporter, err := NewElasticSearchReporter()
		if err != nil {
			return nil, fmt.Errorf("unable to create elasticsearch reporter: %w", err)
		}
		reporterComposite.reporters["elasticsearch"] = reporter
	}

	return &reporterComposite, nil
}

func (rc *ReporterComposite) ReportAssessment(hostAssessment HostAssessment, safeVersion Semver) error {
	for _, reporter := range rc.reporters {
		err := reporter.ReportAssessment(hostAssessment, safeVersion)
		if err != nil {
			return err
		}
	}
	return nil
}

func (rc *ReporterComposite) ReportError(fqdn string, anError error) error {
	for _, reporter := range rc.reporters {
		err := reporter.ReportError(fqdn, anError)
		if err != nil {
			return err
		}
	}
	return nil
}
