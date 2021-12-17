package detector

type Reporter interface {
	Report(hostAssessment HostAssessment)
}
