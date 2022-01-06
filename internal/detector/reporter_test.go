package detector

import (
	"fmt"
	"testing"

	gomock "github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestReportAssessment(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	reporter, err := NewReporterComposite([]string{"stdout"})
	assert.NoError(t, err)

	assessment := HostAssessment{
		FQDN: "fqdn",
	}

	m := NewMockReporter(ctrl)
	reporter.reporters["test"] = m

	m.EXPECT().
		ReportAssessment(gomock.Eq(assessment)).
		Return(nil)

	err = reporter.ReportAssessment(assessment)
	assert.NoError(t, err)
}

func TestReportError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	reporter, err := NewReporterComposite([]string{"stdout"})
	assert.NoError(t, err)
	anError := fmt.Errorf("test error")

	m := NewMockReporter(ctrl)
	reporter.reporters["test"] = m

	m.EXPECT().
		ReportError(gomock.Eq("fqdn"), gomock.Eq(anError)).
		Return(nil)

	err = reporter.ReportError("fqdn", anError)
	assert.NoError(t, err)
}
