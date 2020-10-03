package main

import (
	"errors"
	"flag"
	"fmt"
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
)

// HTTPClient is an interface for fetching HTTP responses.
type HTTPClient interface {
	Get(string) (*http.Response, error)
	Do(req *http.Request) (*http.Response, error)
}

func main() {
	flag.Usage = func() {
		fmt.Printf("usage: %s <command> <pem>\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	//nolint:gomnd
	if flag.NArg() < 2 {
		flag.Usage()
		os.Exit(1)
	}

	// TODO: move to method that returns both cert + issuer?
	path := os.Args[2]

	cert, err := readCertificate(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}

	httpClient := &http.Client{}
	client := NewClient(httpClient, os.Stdout)

	switch os.Args[1] {
	case "ocsp":
		client.CheckCertificateStatusOCSP(cert)
	case "crl":
		client.CheckCertificateStatusCRL(cert)
	default:
		flag.PrintDefaults()
		os.Exit(1)
	}
}
