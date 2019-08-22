package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/wiardvanrij/worker/parser"
)

type Response struct {
	Entries []Entry `json:"entries"`
}

type Entry struct {
	LeafInput string `json:"leaf_input"`
	ExtraData string `json:"extra_data"`
}

type CertJob struct {
	Cert    *x509.Certificate
	Success bool
}

func parse(id int, entry <-chan Entry, results chan<- CertJob) {
	for job := range entry {

		var certJob CertJob
		certJob.Success = false

		// fmt.Println("worker started with ID: ", id)

		decoded, err := base64.StdEncoding.DecodeString(job.LeafInput)
		if err != nil {
			fmt.Println(err)
		}

		decodedExtra, err := base64.StdEncoding.DecodeString(job.ExtraData)
		if err != nil {
			fmt.Println(err)
		}

		var result *parser.Entry
		result, _ = parser.ParseEntry(decoded, decodedExtra)

		if result.Type == 0 {
			cert, _ := x509.ParseCertificate(result.X509Cert)
			//json, _ := json.Marshal(&cert)
			// fmt.Println(cert.DNSNames)
			// fmt.Println("worker", id, "finished job")
			certJob.Cert = cert
			certJob.Success = true
		}

		results <- certJob
	}

}

func main() {
	start := time.Now()

	response := doRequest()
	maxLenght := len(response.Entries)

	jobs := make(chan Entry, maxLenght)
	results := make(chan CertJob, maxLenght)

	for w := 1; w <= 100; w++ {
		go parse(w, jobs, results)
	}

	fmt.Println(maxLenght)
	for _, entry := range response.Entries {
		jobs <- entry
	}
	close(jobs)

	for i := 1; i <= maxLenght; i++ {
		certJob := <-results
		fmt.Println(certJob.Success)
	}

	elapsed := time.Since(start)
	log.Printf("Run took %s", elapsed)

}

func doRequest() Response {
	response, err := http.Get("https://ct.googleapis.com/rocketeer/ct/v1/get-entries?start=1&end=2000")

	if err != nil {
		fmt.Print(err.Error())
	}

	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Print(err.Error())
	}

	var responseObject Response
	json.Unmarshal(responseData, &responseObject)

	return responseObject
}
