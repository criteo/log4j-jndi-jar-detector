package detector

import "time"

type HostAssessment struct {
	Hostname                         string
	ApplicationAssessments           []ApplicationAssessment
	ApplicationAssessmentErrors      []ApplicationAssessmentError
	VulnerableApplicationAssessments []ApplicationAssessment
	StartTime                        time.Time
	EndTime                          time.Time
}

func NewHostAssessment(hostname string, appAssessments []ApplicationAssessment,
	appAssessmentErrors []ApplicationAssessmentError, startTime, endTime time.Time) HostAssessment {
	vulnerableAppAssessments := []ApplicationAssessment{}
	for _, appAssessment := range appAssessments {
		if appAssessment.IsVulnerable() {
			vulnerableAppAssessments = append(vulnerableAppAssessments, appAssessment)
		}
	}
	return HostAssessment{
		Hostname:                         hostname,
		ApplicationAssessments:           appAssessments,
		ApplicationAssessmentErrors:      appAssessmentErrors,
		VulnerableApplicationAssessments: vulnerableAppAssessments,
		StartTime:                        startTime,
		EndTime:                          endTime,
	}
}

func (ha HostAssessment) ToReport() map[string]interface{} {
	return map[string]interface{}{
		"kind":                   "host",
		"hostname":               ha.Hostname,
		"nb_java_processes":      len(ha.ApplicationAssessments),
		"nb_vuln_java_processes": len(ha.VulnerableApplicationAssessments),
		"run_start_time":         ha.StartTime.Format(time.RFC3339),
		"run_end_time":           ha.EndTime.Format(time.RFC3339),
		"duration":               ha.EndTime.Sub(ha.StartTime).Seconds(),
	}
}
