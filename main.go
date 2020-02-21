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
	"time"

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

func parse(entry []Entry) []*x509.Certificate {

	var results []*x509.Certificate

	for _, job := range entry {

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
					results = append(results, cert)
				}
			}
		}

	}
	return results
}

func main() {

	url := os.Getenv("url")
	limit := os.Getenv("limit")
	interval := os.Getenv("interval")

	url = "https://oak.ct.letsencrypt.org/2020"
	limit = "20"
	interval = "5000"

	limitInt, err := strconv.Atoi(limit)
	if err == nil {
		fmt.Println(err)
	}

	intervalInt, err := strconv.Atoi(interval)
	if err == nil {
		fmt.Println(err)
	}

	intervalTime := float64(intervalInt)

	startFetch(url, limitInt, intervalTime)

	select {}

}

func startFetch(url string, limit int, intervalTime float64) {

	head, err := fetchHead(url + "/ct/v1/get-sth")
	if err != nil {
		fmt.Println(err)
		// Lets sleep to give head some time
		log.Fatal("cannot get head.hehe")
	}
	start := head.TreeSize
	end := 0

	sleep := 0

	ticker := time.NewTicker(time.Duration(intervalTime) * time.Millisecond)
	go func() {
		for t := range ticker.C {

			if sleep > 0 {
				sleep--
				continue
			}
			fmt.Println("Tick at", t, url)

			head, err := fetchHead(url + "/ct/v1/get-sth")
			if err != nil {
				fmt.Println(err)
				sleep = 3
				continue
			}

			if head.TreeSize > (start+limit)-1 {
				end = (start + limit) - 1
			} else if head.TreeSize == start-1 {
				fmt.Println("up to date, waiting")
				sleep = 3
				continue
			} else {
				end = head.TreeSize
			}

			endString := strconv.Itoa(end)
			startString := strconv.Itoa(start)
			fmt.Println("Start: " + startString + "End: " + endString)
			response, err := doRequest(url + "/ct/v1/get-entries?start=" + startString + "&end=" + endString)
			if err != nil {
				fmt.Println(err)
				sleep = 3
				continue
			}
			start = end + 1

			fmt.Println("start initRequest now")

			go initRequests(response)
		}
	}()
}

func initRequests(response Response) {

	certs := parse(response.Entries)

	kafkaURL := "localhost:9092"
	topic := "certlog"
	writer := newKafkaWriter(kafkaURL, topic)
	defer writer.Close()

	for _, cert := range certs {

		certPush := CertificatePush{
			Version:               cert.Version,
			SerialNumber:          cert.SerialNumber,
			Issuer:                cert.Issuer,
			Subject:               cert.Subject,
			NotBefore:             cert.NotBefore,
			NotAfter:              cert.NotAfter,
			OCSPServer:            cert.OCSPServer,
			IssuingCertificateURL: cert.IssuingCertificateURL,
			DNSNames:              cert.DNSNames,
			EmailAddresses:        cert.EmailAddresses,
			CRLDistributionPoints: cert.CRLDistributionPoints,
		}

		json, err := json.Marshal(&certPush)
		if err != nil {
			fmt.Println(err)
		} else {
			msg := kafka.Message{
				Key:   []byte(fmt.Sprintf("cert-%d", cert.SerialNumber)),
				Value: []byte(json),
			}
			err := writer.WriteMessages(context.Background(), msg)
			if err != nil {
				fmt.Println(err)
			}
		}
	}
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
