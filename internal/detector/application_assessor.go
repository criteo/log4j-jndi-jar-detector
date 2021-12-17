package detector

type ApplicationAssessor struct {
	jarAssessor JarAssessor
}

func NewApplicationAssessor(jarChecker JarChecker) *ApplicationAssessor {
	return &ApplicationAssessor{
		jarAssessor: NewJarAssessor(jarChecker),
	}
}

func (aa *ApplicationAssessor) Assess(application Application) (*ApplicationAssessment, error) {
	jarAssessments := make([]JarAssessement, 0)

	for _, jarPath := range application.Jars {
		jarAssessment, err := aa.jarAssessor.Assess(jarPath)
		if err != nil {
			return nil, err
		}
		jarAssessments = append(jarAssessments, *jarAssessment)
	}
	applicationAssessment := ApplicationAssessment{
		Application:    application,
		JarAssessments: jarAssessments,
	}
	return &applicationAssessment, nil
}
