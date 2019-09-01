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
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-pg/pg"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/snappy"
	"github.com/wiardvanrij/worker/parser"
)

const addr = "postgres-postgresql.postgres.svc.cluster.local:5432"
const user = "postgres"
const password = "postgrespass"
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
	LogId                 int
	LogUrl                string
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
				} else {
					certJob.Cert = cert
					certJob.Success = true
				}
			}
		}

		results <- certJob
	}
}

func main() {

	id := os.Getenv("id")
	url := os.Getenv("url")
	limit := os.Getenv("limit")
	interval := os.Getenv("interval")

	idInt, err := strconv.Atoi(id)
	if err == nil {
		fmt.Println(err)
	}

	limitInt, err := strconv.Atoi(limit)
	if err == nil {
		fmt.Println(err)
	}

	intervalInt, err := strconv.Atoi(interval)
	if err == nil {
		fmt.Println(err)
	}

	intervalTime := float64(intervalInt)

	startFetch(idInt, url, limitInt, intervalTime)

	// startFetch(1, "https://ct.googleapis.com/rocketeer")
	// startFetch(2, "https://oak.ct.letsencrypt.org/2019")
	// startFetch(3, "https://ct.googleapis.com/logs/argon2019")
	//startFetch(4, "https://ct.googleapis.com/logs/xenon2019")
	// startFetch(5, "https://ct.cloudflare.com/logs/nimbus2019")

	select {}

}

func startFetch(id int, url string, limit int, intervalTime float64) {

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
	Database.Close()

	start := dboffset.Offset
	end := 0
	ticketC := 0

	if start == 1 {
		_, set := os.LookupEnv("fromEnd")
		if set {
			head, err := fetchHead(url + "/ct/v1/get-sth")
			if err != nil {
				fmt.Println(err)
				// Lets sleep to give head some time
				log.Fatal("cannot get head.hehe")
			}
			start = head.TreeSize
			fmt.Printf("sleeping 5 seconds to give head some time to update")
			time.Sleep(5 * time.Second)
		}
	}

	sleep := 0

	ticker := time.NewTicker(time.Duration(intervalTime) * time.Millisecond)
	go func() {
		for t := range ticker.C {
			ticketC++
			fmt.Println("Tick at", t, url)

			if sleep > 0 {
				fmt.Println("Sleeping ", sleep)
				sleep--
				continue
			}

			head, err := fetchHead(url + "/ct/v1/get-sth")
			if err != nil {
				fmt.Println(err)
				continue
			}

			if head.TreeSize > (start+limit)-1 {
				end = (start + limit) - 1
			} else if head.TreeSize == start-1 {
				fmt.Println("up to date, waiting")
				sleep = 5
				continue
			} else {
				end = head.TreeSize
			}

			endString := strconv.Itoa(end)
			startString := strconv.Itoa(start)
			fmt.Println("Start: " + startString + "End: " + endString)
			response, err := doRequest(url + "/ct/v1/get-entries?start=" + startString + "&end=" + endString)
			if err != nil {
				continue
			}
			start = end + 1
			go initRequests(response, url, id)

			if ticketC == 60 {
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

				Database.Close()

			}

		}
	}()
}

func initRequests(response Response, url string, id int) {

	maxLength := len(response.Entries)
	jobs := make(chan Entry, maxLength)
	results := make(chan CertJob, maxLength)

	for w := 1; w <= 20; w++ {
		go parse(w, jobs, results)
	}

	for _, entry := range response.Entries {
		jobs <- entry
	}
	close(jobs)

	buffers := make(chan bool, 100)
	var wg sync.WaitGroup

	kafkaURL := "kafka-headless.kafka:9092"
	topic := "certlog"
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
					LogId:                 id,
					LogUrl:                url,
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
						Key:   []byte(fmt.Sprintf("cert-%d", certJob.Cert.SerialNumber)),
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
		Brokers:          []string{kafkaURL},
		Topic:            topic,
		Balancer:         &kafka.LeastBytes{},
		CompressionCodec: snappy.NewCompressionCodec(),
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
