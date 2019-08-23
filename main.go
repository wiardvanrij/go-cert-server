package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-pg/pg"
	"github.com/segmentio/kafka-go"
	"github.com/wiardvanrij/worker/parser"
)

const addr = "localhost:5432"
const user = "postgres"
const password = "password"
const database = "postgres"

type DBOffset struct {
	Id         int
	Offset     int
	LastUpdate time.Time
}

type Response struct {
	Entries []Entry `json:"entries"`
}

type STHResponse struct {
	TreeSize          int    `json:"tree_size"`
	Timestamp         int64  `json:"timestamp"`
	SHA256rootHash    string `json:"sha256_root_hash"`
	TreeHeadSignature string `json:"tree_head_signature"`
}

type Entry struct {
	LeafInput string `json:"leaf_input"`
	ExtraData string `json:"extra_data"`
}

type CertJob struct {
	Cert    *x509.Certificate
	Success bool
}

type CertificatePush struct {
	Version               int
	SerialNumber          *big.Int
	Issuer                pkix.Name
	Subject               pkix.Name
	NotBefore, NotAfter   time.Time // Validity bounds.
	OCSPServer            []string
	IssuingCertificateURL []string
	DNSNames              []string
	EmailAddresses        []string
	CRLDistributionPoints []string
}

func parse(id int, entry <-chan Entry, results chan<- CertJob) {
	for job := range entry {

		var certJob CertJob
		certJob.Success = false

		decoded, err := base64.StdEncoding.DecodeString(job.LeafInput)
		if err != nil {
			fmt.Println(err)
		}

		decodedExtra, err := base64.StdEncoding.DecodeString(job.ExtraData)
		if err != nil {
			fmt.Println(err)
		}

		var result *parser.Entry
		result, errParse := parser.ParseEntry(decoded, decodedExtra)
		if errParse != nil {
			fmt.Println(errParse)
		} else {
			if result.Type == 0 {
				cert, err := x509.ParseCertificate(result.X509Cert)
				if err != nil {
					fmt.Println(err)
				}
				certJob.Cert = cert
				certJob.Success = true
			}
		}

		results <- certJob
	}
}

func main() {

	startFetch(1, "https://ct.googleapis.com/rocketeer")
	startFetch(2, "https://oak.ct.letsencrypt.org/2019")
	startFetch(3, "https://oak.ct.letsencrypt.org/2020")
	startFetch(4, "https://oak.ct.letsencrypt.org/2021")

	//time.Sleep(10 * time.Minute)

}

func startFetch(id int, url string) {

	var Database *pg.DB
	Database = pg.Connect(&pg.Options{
		Addr:     addr,
		User:     user,
		Password: password,
		Database: database,
	})

	defer Database.Close()
	dboffset := &DBOffset{Id: id}
	err := Database.Select(dboffset)
	if err != nil {
		log.Fatal(err)
	}

	start := dboffset.Offset
	limit := 100
	end := 0
	ticketC := 0

	ticker := time.NewTicker(1 * time.Second)
	go func() {
		for t := range ticker.C {
			ticketC++
			fmt.Println("Tick at", t, url)
			head, err := fetchHead(url + "/ct/v1/get-sth")
			if err != nil {
				// Lets sleep to give head some time
				fmt.Println("sleep at head")
				time.Sleep(1 * time.Minute)
				continue
			}

			if head.TreeSize > (start+limit)-1 {
				end = (start + limit) - 1
			} else if head.TreeSize == start {
				fmt.Println("up to date, waiting")
				time.Sleep(10 * time.Second)
				continue
			} else {
				end = head.TreeSize
			}

			endString := strconv.Itoa(end)
			startString := strconv.Itoa(start)

			response, err := doRequest(url + "/ct/v1/get-entries?start=" + startString + "&end=" + endString)
			if err != nil {
				// Lets sleep to give entries some time
				fmt.Println("sleep at entries")
				time.Sleep(30 * time.Second)
				continue
			}
			start = end + 1
			initRequests(response, url)

			if ticketC == 10 {
				ticketC = 0
				var Database *pg.DB
				Database = pg.Connect(&pg.Options{
					Addr:     addr,
					User:     user,
					Password: password,
					Database: database,
				})
				defer Database.Close()

				dboffset := &DBOffset{Id: id}
				err := Database.Select(dboffset)
				if err != nil {
					fmt.Println(err)

				}

				dboffset.Offset = end
				dboffset.LastUpdate = time.Now()

				err = Database.Update(dboffset)
				if err != nil {
					fmt.Println(err)
					fmt.Println("updateJobDBUpdate")
				}

			}

		}
	}()
}

func initRequests(response Response, url string) {

	maxLength := len(response.Entries)
	jobs := make(chan Entry, maxLength)
	results := make(chan CertJob, maxLength)

	for w := 1; w <= 100; w++ {
		go parse(w, jobs, results)
	}

	for _, entry := range response.Entries {
		jobs <- entry
	}
	close(jobs)

	buffers := make(chan bool, 100)
	var wg sync.WaitGroup

	kafkaURL := "127.0.0.1:9092"
	topic := "testing5"
	writer := newKafkaWriter(kafkaURL, topic)
	defer writer.Close()

	count := 0
	countBad := 0
	i := 1

	for i <= maxLength {
		i++
		//<-results
		certJob := <-results
		if certJob.Success {
			wg.Add(1)

			go func() {
				buffers <- true

				certPush := CertificatePush{
					Version:               certJob.Cert.Version,
					SerialNumber:          certJob.Cert.SerialNumber,
					Issuer:                certJob.Cert.Issuer,
					Subject:               certJob.Cert.Subject,
					NotBefore:             certJob.Cert.NotBefore,
					NotAfter:              certJob.Cert.NotAfter,
					OCSPServer:            certJob.Cert.OCSPServer,
					IssuingCertificateURL: certJob.Cert.IssuingCertificateURL,
					DNSNames:              certJob.Cert.DNSNames,
					EmailAddresses:        certJob.Cert.EmailAddresses,
					CRLDistributionPoints: certJob.Cert.CRLDistributionPoints,
				}

				json, err := json.Marshal(&certPush)
				if err != nil {

				} else {
					msg := kafka.Message{
						Key:   []byte(fmt.Sprintf("Key-%d", i)),
						Value: []byte(json),
					}
					err := writer.WriteMessages(context.Background(), msg)
					if err != nil {
						fmt.Println(err)
					}
					count++
				}

				<-buffers
				wg.Done()
			}()

		} else {
			countBad++
		}
	}
	wg.Wait()
	fmt.Println("succes", count)
	fmt.Println("bad", countBad)
	fmt.Println("iteration", i)
}

func newKafkaWriter(kafkaURL, topic string) *kafka.Writer {
	return kafka.NewWriter(kafka.WriterConfig{
		Brokers:  []string{kafkaURL},
		Topic:    topic,
		Balancer: &kafka.LeastBytes{},
	})
}

func fetchHead(url string) (STHResponse, error) {
	response, err := http.Get(url)

	var responseObject STHResponse

	if err != nil {
		return responseObject, err
	}

	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return responseObject, err
	}

	err = json.Unmarshal(responseData, &responseObject)
	if err != nil {
		return responseObject, err
	}

	return responseObject, nil
}

func doRequest(url string) (Response, error) {
	var responseObject Response
	response, err := http.Get(url)

	if err != nil {
		return responseObject, err
	}

	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return responseObject, err
	}

	err = json.Unmarshal(responseData, &responseObject)
	if err != nil {
		return responseObject, err
	}

	return responseObject, nil
}
