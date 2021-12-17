package detector

type ApplicationAssessmentError struct {
	Application Application
	Message     string
}

func (aae ApplicationAssessmentError) ToReport() map[string]interface{} {
	return map[string]interface{}{
		"kind":       "application_assessment_error",
		"appname":    aae.Application.Cmdline,
		"username":   aae.Application.Username,
		"workingdir": aae.Application.Cwd,
		"message":    aae.Message,
	}
}
