package detector

import "strings"

type ApplicationAssessmentError struct {
	Application Application
	Message     string
}

func (aae ApplicationAssessmentError) ToReport() map[string]interface{} {
	return map[string]interface{}{
		"kind":       "application_assessment_error",
		"appname":    strings.Join(aae.Application.CmdlineSlice, " "),
		"username":   aae.Application.Username,
		"workingdir": aae.Application.Cwd,
		"message":    aae.Message,
	}
}
