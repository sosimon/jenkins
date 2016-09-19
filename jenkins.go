package jenkins

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Jenkins struct
type Jenkins struct {
	BaseURL    string
	User       string
	Token      string
	httpClient *http.Client
}

// ConfigXML struct
type ConfigXML struct {
	XMLName          xml.Name
	StringParameters []StringParameter `xml:"properties>hudson.model.ParametersDefinitionProperty>parameterDefinitions>hudson.model.StringParameterDefinition"`
}

// StringParameter struct
type StringParameter struct {
	Name         string `xml:"name"`
	DefaultValue string `xml:"defaultValue"`
}

// JobsXML struct
type JobsXML struct {
	XMLName xml.Name
	Jobs    []Job `xml:"job"`
}

// Job struct
type Job struct {
	Name            string `xml:"name"`
	URL             string `xml:"url"`
	NextBuildNumber string `xml:"nextBuildNumber"`
}

// CreateNodeJSON is used for creating nodes (slaves) in Jenkins
type CreateNodeJSON struct {
	// Name of the node
	// Could be anything but usually an IP or hostname
	Name string `json:"name"`

	// Description of the node (not required)
	NodeDescription string `json:"nodeDescription"`

	// Number of threads/executors available on this node
	NumExecutors int `json:"numExecutors"`

	// Remote root directory, usually `/app`
	RemoteFS string `json:"remoteFS"`

	// Label, usually `electrode`
	LabelString string `json:"labelString"`

	// Usage, either NORMAL or EXCLUSIVE
	// NORMAL: Use this node as much as possible
	// EXCLUSIVE: Only build jobs with label expressions matching this node
	Mode string `json:"mode"`

	// Hardcode to "hudson.slaves.DumbSlave"
	Type string `json:"type"`

	// Launch method
	// We launch via SSH -> which translates to
	// launcher["stapler-class"] = "hudson.plugins.sshslaves.SSHLauncher"
	// launcher["credentialsId"] = "eea9ba64-e06c-4b38-b7e5-0f220830cd98"
	Launcher map[string]string `json:"launcher"`

	// Hardcode
	// rs["stapler-class"] = "hudson.slaves.RetentionStrategy$Always"
	RetentionStrategy map[string]string `json:"retentionStrategy"`

	// Hardcode
	// np["stapler-class-bag"] = "true"
	NodeProperties map[string]string `json:"nodeProperties"`
}

const (
	jobsQuery = "api/xml?tree=jobs[name,url,nextBuildNumber]"
)

// NewJenkins initializes and returns a Jenkins struct
// Jenkins objects should be created this way, ideally
func NewJenkins() *Jenkins {
	if os.Getenv("JENKINS_USER") == "" || os.Getenv("JENKINS_TOKEN") == "" {
		panic(errors.New("Missing required Jenkins credentials JENKINS_USER and/or JENKINS_TOKEN"))
	}
	return &Jenkins{
		BaseURL:    "http://localhost:8080/",
		User:       os.Getenv("JENKINS_USER"),
		Token:      os.Getenv("JENKINS_TOKEN"),
		httpClient: &http.Client{},
	}
}

// CreateNode creates a Jenkins slave node with name and description
// set to its hostname or IP
func (j *Jenkins) CreateNode(nodeName string) error {
	// Check if node exists
	if j.IsNodeExists(nodeName) {
		log.Printf("ERROR: Node %s exists already", nodeName)
		return errors.New("Node exists already")
	}

	// Initialize maps to build JSON for node creation
	// RetentionStrategy
	rs := make(map[string]string)
	rs["stapler-class"] = "hudson.slaves.RetentionStrategy$Always"

	// NodeProperties
	np := make(map[string]string)
	np["stapler-class-bag"] = "true"

	// Launcher
	l := make(map[string]string)
	l["stapler-class"] = "hudson.plugins.sshslaves.SSHLauncher"
	l["host"] = nodeName
	l["port"] = "22"
	l["credentialsId"] = "eea9ba64-e06c-4b38-b7e5-0f220830cd98"

	createNodeJSON := CreateNodeJSON{
		Name:              nodeName,
		NodeDescription:   nodeName,
		NumExecutors:      4,
		RemoteFS:          "/app",
		LabelString:       "electrode",
		Mode:              "EXCLUSIVE",
		Type:              "hudson.slaves.DumbSlave",
		RetentionStrategy: rs,
		NodeProperties:    np,
		Launcher:          l,
	}

	// Convert struct to JSON string
	jsonBS, _ := json.Marshal(createNodeJSON)
	jsonStr := string(jsonBS)

	// Prepare URL parameters for the HTTP request
	urlValues := &url.Values{
		"name": {nodeName},
		"type": {"hudson.slaves.DumbSlave"},
		"json": {jsonStr},
	}

	createURL := j.BaseURL + "computer/doCreateItem"

	req, err := http.NewRequest("POST", createURL, strings.NewReader(urlValues.Encode()))
	if err != nil {
		log.Println(err)
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(j.User, j.Token)

	_, err = j.httpClient.Do(req)
	if err != nil {
		log.Println(err)
		return err
	}

	// res.Status will be 403 Forbidden if successful *facepalm*
	// Check again to see if the node was actually created
	if !j.IsNodeExists(nodeName) {
		log.Printf("ERROR: Node %s does not exist", nodeName)
		return errors.New("Create node failed")
	}

	log.Printf("Node %s created successfully", nodeName)

	return nil
}

// DeleteNode deletes node with nodeName
func (j *Jenkins) DeleteNode(nodeName string) error {
	if !j.IsNodeExists(nodeName) {
		log.Println("Node does not exist")
		return nil
	}
	url := j.BaseURL + "computer/" + nodeName + "/doDelete"
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		log.Println(err)
		return err
	}
	req.SetBasicAuth(j.User, j.Token)
	_, err = j.httpClient.Do(req)
	if err != nil {
		log.Println(err)
		return err
	}
	// Check to make sure node is gone
	if j.IsNodeExists(nodeName) {
		log.Printf("ERROR: Delete node %s failed", nodeName)
		return errors.New("Delete node failed")
	}

	log.Printf("Node %s deleted successfully", nodeName)

	return nil
}

// IsNodeExists checks if node with nodeName exists
func (j *Jenkins) IsNodeExists(nodeName string) bool {
	url := j.BaseURL + "computer/" + nodeName + "/api/xml"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalln(err)
	}
	req.SetBasicAuth(j.User, j.Token)
	res, err := j.httpClient.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	if res.StatusCode != 200 {
		return false
	}
	return true
}

// GetAllJobs lists all Jenkins jobs, recursively
// Fetches via Jenkins API
func (j *Jenkins) GetAllJobs() error {
	var jobsList []Job
	var wg sync.WaitGroup
	jobsCh := make(chan Job)

	start := time.Now()

	wg.Add(1)
	go j.fetch(&wg, jobsCh, j.BaseURL)
	go func() {
		wg.Wait()
		close(jobsCh)
	}()

	for job := range jobsCh {
		jobsList = append(jobsList, job)
	}

	for _, job := range jobsList {
		fmt.Printf("%s\n", j.getJobKey(job.URL))
	}

	elapsed := time.Since(start).Seconds()
	log.Printf("%d jobs found\n", len(jobsList))
	log.Printf("Took %fs\n", elapsed)
	return nil
}

// goroutine for GetAllJobs
func (j *Jenkins) fetch(wg *sync.WaitGroup, jobsCh chan Job, baseURL string) {
	defer wg.Done()

	url := baseURL + jobsQuery
	body, err := j.get(url)
	if err != nil {
		panic(err)
	}

	var v JobsXML
	err = xml.Unmarshal(body, &v)
	if err != nil {
		panic(err)
	}

	for _, job := range v.Jobs {
		if j.isFolder(job) {
			wg.Add(1)
			go j.fetch(wg, jobsCh, job.URL)
		} else {
			jobsCh <- job
		}
	}
}

// GetJobParams gets and prints all the string parameters for a job
func (j *Jenkins) GetJobParams(jobKey string) error {
	url := j.getJobURL(jobKey) + "/config.xml"
	body, err := j.get(url)
	if err != nil {
		return err
	}
	var v ConfigXML
	err = xml.Unmarshal(body, &v)
	if err != nil {
		return err
	}
	for _, param := range v.StringParameters {
		log.Printf("%s=%s\n", param.Name, param.DefaultValue)
	}
	return nil
}

// GetJobConfig gets and prints config.xml
func (j *Jenkins) GetJobConfig(jobKey string) error {
	url := j.getJobURL(jobKey) + "/config.xml"
	body, err := j.get(url)
	if err != nil {
		return err
	}
	log.Printf("%s\n", string(body))
	return nil
}

// UpdateJob POST a config.xml file to Jenkins
// jobKey example: "MiBS/Test"
// cfgFilePath example: "configs/MiBS/Test/config.xml"
func (j *Jenkins) UpdateJob(jobKey string, cfgFilePath string) {
	url := j.getJobURL(jobKey) + "/config.xml"
	err := j.post(url, cfgFilePath)
	if err != nil {
		log.Printf("%s\n", err)
	}
}

// CreateFolder creates an empty folder
// Requires an `empty_folder.xml` template
func (j *Jenkins) CreateFolder(jobKey string) error {
	url := j.getCreateJobURL(jobKey)
	err := j.post(url, "configs/empty_folder.xml")
	if err != nil {
		return err
	}
	return nil
}

// CreateJob creates a job based on cfgFilePath template
func (j *Jenkins) CreateJob(jobKey string, cfgFilePath string) error {
	log.Printf("%s\n", cfgFilePath)
	url := j.getCreateJobURL(jobKey)
	err := j.post(url, cfgFilePath)
	if err != nil {
		return err
	}
	return nil
}

func (j *Jenkins) isFolder(job Job) bool {
	if job.NextBuildNumber != "" {
		return false
	}
	return true
}

func (j *Jenkins) get(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(j.User, j.Token)
	res, err := j.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (j *Jenkins) post(url string, file string) error {
	body, err := os.Open(file)
	if err != nil {
		return err
	}
	defer body.Close()
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(j.User, j.Token)
	req.Header.Set("Content-Type", "application/xml")
	res, err := j.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	return nil
}

func (j *Jenkins) getCreateJobURL(jobKey string) string {
	split := strings.Split(strings.Trim(jobKey, "/"), "/")
	var path, jobName string
	jobName = split[len(split)-1]
	if len(split) > 1 {
		path = "job/" + strings.Join(split[:len(split)-1], "/job/") + "/"
	}
	url := j.BaseURL + path + "createItem?name=" + jobName
	return url
}

func (j *Jenkins) getJobURL(jobKey string) string {
	url := j.BaseURL + "job/" + strings.Replace(strings.Trim(jobKey, "/"), "/", "/job/", -1)
	return url
}

func (j *Jenkins) getJobKey(jobURL string) string {
	key := strings.Join(strings.Split(jobURL, "job/")[1:], "")
	return key
}
