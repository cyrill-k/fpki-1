package logpicker

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	ct "github.com/google/certificate-transparency-go"
	ctTls "github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	ctX509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/domain"
)

// CertData: data structure of leaf from CT log
type CertData struct {
	LeafInput string `json:"leaf_input"`
	ExtraData string `json:"extra_data"`
}

// CertLog: Data from CT log
type CertLog struct {
	Entries []CertData
}

// certResult: Used in worker threads
type certResult struct {
	Err   error
	Certs []*x509.Certificate
}

// UpdateDomainFromLog: Fetch certificates from CT log
func GetCertMultiThread(ctURL string, startIndex int64, endIndex int64, numOfWorker int) ([]*x509.Certificate, error) {
	gap := (endIndex - startIndex) / int64(numOfWorker)
	resultChan := make(chan certResult)
	for i := 0; i < numOfWorker-1; i++ {
		go workerThread(ctURL, startIndex+int64(i)*gap, startIndex+int64(i+1)*gap-1, resultChan)
	}
	// last work take charge of the rest of the queries
	// Because var "gap" might be rounded.
	go workerThread(ctURL, startIndex+int64(numOfWorker-1)*gap, endIndex, resultChan)

	certResult := []*x509.Certificate{}
	for i := 0; i < numOfWorker; i++ {
		newResult := <-resultChan
		if newResult.Err != nil {
			return nil, fmt.Errorf("UpdateDomainFromLog | %w", newResult.Err)
		}
		certResult = append(certResult, newResult.Certs...)
	}

	close(resultChan)
	return certResult, nil
}

// workerThread: worker thread for log picker
func workerThread(ctURL string, start, end int64, resultChan chan certResult) {
	var certs []*x509.Certificate
	for i := start; i < end; i += 20 {
		var newCerts []*x509.Certificate
		var err error
		// TODO(yongzhe): better error handling; retry if error happens
		if end-i > 20 {
			newCerts, err = getCerts(ctURL, i, i+19)
			if err != nil {
				resultChan <- certResult{Err: err}
				continue
			}
		} else {
			newCerts, err = getCerts(ctURL, i, i+end-i)
			if err != nil {
				resultChan <- certResult{Err: err}
				continue
			}
		}
		certs = append(certs, newCerts...)
	}
	resultChan <- certResult{Certs: certs}
}

// get certificate from CT log
func getCerts(ctURL string, start int64, end int64) ([]*ctX509.Certificate, error) {
	url := fmt.Sprintf(ctURL+"/ct/v1/get-entries?start=%d&end=%d&quot", start, end)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("getCerts | http.Get %w", err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)

	var resultsCerLog CertLog
	json.Unmarshal(buf.Bytes(), &resultsCerLog)

	certList := []*ctX509.Certificate{}

	// parse merkle leaves and append it to the result
	for _, entry := range resultsCerLog.Entries {
		leafBytes, _ := base64.RawStdEncoding.DecodeString(entry.LeafInput)
		var merkleLeaf ct.MerkleTreeLeaf
		ctTls.Unmarshal(leafBytes, &merkleLeaf)

		var certificate *ctX509.Certificate
		switch entryType := merkleLeaf.TimestampedEntry.EntryType; entryType {
		case ct.X509LogEntryType:
			certificate, err = ctX509.ParseCertificate(merkleLeaf.TimestampedEntry.X509Entry.Data)
			if err != nil {
				fmt.Println("ERROR: ParseCertificate ", err)
				continue
			}
		case ct.PrecertLogEntryType:
			certificate, err = ctX509.ParseTBSCertificate(merkleLeaf.TimestampedEntry.PrecertEntry.TBSCertificate)
			if err != nil {
				fmt.Println("ERROR: ParseTBSCertificate ", err)
				continue
			}
		}
		certList = append(certList, certificate)
	}

	return certList, nil
}

// GetPCAndRPC: get PC and RPC from url
// TODO(yongzhe): currently just generate random PC and RPC using top 1k domain names
func GetPCAndRPC(ctURL string, startIndex int64, endIndex int64, numOfWorker int) ([]*common.PC, []*common.RPC, error) {
	domainParser, err := domain.NewDomainParser()
	if err != nil {
		return nil, nil, fmt.Errorf("GetPCAndRPC | NewDomainParser | %w", err)
	}
	resultPC := []*common.PC{}
	resultRPC := []*common.RPC{}

	f, err := os.Open(ctURL)
	if err != nil {
		return nil, nil, fmt.Errorf("GetPCAndRPC | os.Open | %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// read domain names from files
	for scanner.Scan() {
		domainName := scanner.Text()
		// no policy for TLD
		if !domainParser.IsValidDomain(domainName) {
			fmt.Println("invalid domain name: ", domainName)
			continue
		}
		resultPC = append(resultPC, &common.PC{
			Subject:     domainName,
			TimeStamp:   time.Now(),
			CASignature: generateRandomBytes(),
		})

		resultRPC = append(resultRPC, &common.RPC{
			Subject:   domainName,
			NotBefore: time.Now(),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("GetPCAndRPC | scanner.Err | %w", err)
	}

	return resultPC, resultRPC, nil
}

func generateRandomBytes() []byte {
	token := make([]byte, 40)
	rand.Read(token)
	return token
}
