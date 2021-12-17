package detector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
)

type ElasticSearchReporter struct {
	client *elasticsearch.Client

	indexNameTemplate string
}

func NewElasticSearchReporter(url, username, password, indexNameTemplate string) (*ElasticSearchReporter, error) {
	es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{url},
		Username:  username,
		Password:  password,
	})
	if err != nil {
		log.Fatalf("Error creating the client: %s", err)
	}

	return &ElasticSearchReporter{
		client:            es,
		indexNameTemplate: indexNameTemplate,
	}, nil
}

func (esr *ElasticSearchReporter) index(body io.Reader) (*esapi.Response, error) {
	date := time.Now().UTC().Format("2016-01-02")
	index := fmt.Sprintf("%s.%s", esr.indexNameTemplate, date)
	return esr.client.Index(index, body)
}

func (esr *ElasticSearchReporter) indexMap(doc map[string]interface{}) (*esapi.Response, error) {
	buffer := new(bytes.Buffer)
	err := json.NewEncoder(buffer).Encode(doc)
	if err != nil {
		return nil, err
	}
	return esr.index(buffer)
}

func (esr *ElasticSearchReporter) indexAssessment(assessment map[string]interface{}) error {
	res, err := esr.indexMap(assessment)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("unable to index assessment (status=%d, reason=%s)", res.StatusCode, res.Body)
	}
	return nil
}

func (esr *ElasticSearchReporter) Report(hostAssessment HostAssessment) error {
	err := esr.indexAssessment(hostAssessment.ToReport())
	if err != nil {
		return fmt.Errorf("unable to index host assessment: %s", err)
	}

	for _, appAssessment := range hostAssessment.VulnerableApplicationAssessments {
		doc := appAssessment.ToReport()
		doc["hostname"] = hostAssessment.Hostname
		err := esr.indexAssessment(doc)
		if err != nil {
			return fmt.Errorf("unable to index application assessment: %s", err)
		}
	}

	for _, appAssessmentError := range hostAssessment.ApplicationAssessmentErrors {
		doc := appAssessmentError.ToReport()
		doc["hostname"] = hostAssessment.Hostname
		err := esr.indexAssessment(doc)
		if err != nil {
			return fmt.Errorf("unable to index application assessment error: %s", err)
		}
	}

	return nil
}
