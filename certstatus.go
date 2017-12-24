package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
)

var (
	errFailedToFetchOCSPResponse    = errors.New("failed to fetch OCSP response")
	errFailedToGetResource          = errors.New("failed to get resource")
	errFailedToReadCertificate      = errors.New("failed to read certificate")
	errFailedToReadResponseBody     = errors.New("failed to response body")
	errNoCertificate                = errors.New("no certificate")
	errNoIssuerCertificate          = errors.New("no issuer certificate")
	errNoOCSPServersFound           = errors.New("no OCSP servers found")
	errNoCRLDistributionPointsFound = errors.New("no CRL distribution points found")

	out    io.Writer  = os.Stdout // substituted during testing
	client HttpClient = &http.Client{}
)

// HTTPClient is an interface for fetching HTTP responses
type HttpClient interface {
	Get(string) (*http.Response, error)
	Do(req *http.Request) (*http.Response, error)
}

func main() {
	flag.Usage = func() {
		fmt.Printf("usage: %s <pem>\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	err := printCertificateStatus(client, flag.Args()[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}
}

func printCertificateStatus(client HttpClient, path string) error {
	cert, err := readCertificate(path)

	if err != nil {
		return err
	}

	issuer, err := getIssuerCertificate(client, cert)
	if err != nil {
		return err
	}

	// OCSP
	resp, err := getOCSPResponse(client, cert, issuer)
	if err != nil {
		return err
	}
	printStatusResponse(resp)

	// CRL
	crlresp, err := GetCRLResponse(client, cert)
	//fmt.Print(crlresp.String())
	if crlresp != nil {
		fmt.Print(crlresp.String())
	}

	return nil
}

func certificateFromBytes(bytes []byte) (*x509.Certificate, error) {
	block, bytes := pem.Decode(bytes)

	if block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, errNoCertificate
		}
		bytes = block.Bytes
	}

	return x509.ParseCertificate(bytes)
}

func readCertificate(path string) (*x509.Certificate, error) {
	var in []byte
	var err error

	in, err = ioutil.ReadFile(path)

	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		return nil, errFailedToReadCertificate
	}

	var cert *x509.Certificate
	cert, err = certificateFromBytes(in)

	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		return nil, errFailedToReadCertificate
	}

	return cert, nil
}

func getIssuerCertificate(client HttpClient, cert *x509.Certificate) (*x509.Certificate, error) {
	var (
		issCert *x509.Certificate
	)

	for _, url := range cert.IssuingCertificateURL {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}

		if err != nil {
			return nil, errFailedToGetResource
		}
		defer resp.Body.Close()

		in, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, errFailedToReadResponseBody
		}

		issCert, err = certificateFromBytes(in)
		if err != nil {
			return nil, errNoIssuerCertificate
		}
		break
	}

	if issCert == nil {
		return nil, errNoIssuerCertificate
	}

	return issCert, nil
}
