package detector

import "time"

type HostAssessment struct {
	FQDN                        string
	ApplicationAssessments      []ApplicationAssessment
	ApplicationAssessmentErrors []ApplicationAssessmentError
	StartTime                   time.Time
	EndTime                     time.Time
}

func NewHostAssessment(fqdn string, appAssessments []ApplicationAssessment,
	appAssessmentErrors []ApplicationAssessmentError, startTime, endTime time.Time) HostAssessment {
	return HostAssessment{
		FQDN:                        fqdn,
		ApplicationAssessments:      appAssessments,
		ApplicationAssessmentErrors: appAssessmentErrors,
		StartTime:                   startTime,
		EndTime:                     endTime,
	}
}

func (ha HostAssessment) ToReport() map[string]interface{} {
	vulnerableAppAssessments := []ApplicationAssessment{}
	for _, appAssessment := range ha.ApplicationAssessments {
		if appAssessment.IsVulnerable() {
			vulnerableAppAssessments = append(vulnerableAppAssessments, appAssessment)
		}
	}

	return map[string]interface{}{
		"kind":                   "host",
		"fqdn":                   ha.FQDN,
		"nb_java_processes":      len(ha.ApplicationAssessments),
		"nb_vuln_java_processes": len(vulnerableAppAssessments),
		"run_start_time":         ha.StartTime.Format(time.RFC3339),
		"run_end_time":           ha.EndTime.Format(time.RFC3339),
		"duration":               ha.EndTime.Sub(ha.StartTime).Seconds(),
	}
}
