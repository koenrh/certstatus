package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

var (
	errFailedToFetchOCSPResponse    = errors.New("failed to fetch OCSP response")
	errFailedToGetResource          = errors.New("failed to get resource")
	errFailedToReadCertificate      = errors.New("failed to read certificate")
	errFailedToReadResponseBody     = errors.New("failed to read response body")
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

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s <command> <pem>\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  ocsp    Check certificate revocation status via OCSP\n")
	fmt.Fprintf(os.Stderr, "  crl     Check certificate revocation status via CRL\n")
}

func main() {
	if len(os.Args) < 3 {
		usage()
		os.Exit(1)
	}

	path := os.Args[2]

	cert, err := readCertificate(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	client := NewClient(httpClient, os.Stdout)

	switch os.Args[1] {
	case "ocsp":
		if err := client.CheckCertificateStatusOCSP(cert); err != nil {
			fmt.Fprintf(os.Stderr, "[error] %v\n", err)
			os.Exit(1)
		}
	case "crl":
		if err := client.CheckCertificateStatusCRL(cert); err != nil {
			fmt.Fprintf(os.Stderr, "[error] %v\n", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(1)
	}
}
