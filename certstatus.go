package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

var (
	errFailedToFetchOCSPResponse = errors.New("failed to fetch OCSP response")
	errFailedToGetResource       = errors.New("failed to get resource")
	errFailedToReadCertificate   = errors.New("failed to read certificate")
	errFailedToReadResponseBody  = errors.New("failed to response body")
	errNoCertificate             = errors.New("no certificate")
	errNoIssuerCertificate       = errors.New("no issuer certificate")
	errNoOCSPServersFound        = errors.New("no OCSP servers found")

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

	printCertificateStatus(client, flag.Args()[0])
}

func printCertificateStatus(client HttpClient, path string) {
	cert, err := readCertificate(path)

	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}

	issuer, err := getIssuerCertificate(client, cert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}

	resp, err := getOCSPResponse(client, cert, issuer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}
	printStatusResponse(resp)
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

func getOCSPServer(cert *x509.Certificate) (string, error) {
	ocspServers := cert.OCSPServer
	if len(ocspServers) == 0 {
		return "", errNoOCSPServersFound
	}
	return ocspServers[0], nil
}

func getOCSPResponse(client HttpClient, cert *x509.Certificate, issuer *x509.Certificate) (*ocsp.Response, error) {
	ocspServer, err := getOCSPServer(cert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}

	options := ocsp.RequestOptions{Hash: crypto.SHA1}
	request, err := ocsp.CreateRequest(cert, issuer, &options)

	url, err := url.Parse(ocspServer)

	req, err := http.NewRequest("POST", ocspServer, bytes.NewBuffer(request))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}
	req.Host = url.Hostname()
	req.Header.Set("content-type", "application/ocsp-request")

	response, err := client.Do(req)
	if err != nil {
		return nil, errFailedToFetchOCSPResponse
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}

	parsedResponse, err := ocsp.ParseResponseForCert(body, cert, issuer)

	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}

	return parsedResponse, nil
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

func printStatusResponse(resp *ocsp.Response) {
	fmt.Fprintf(out, "Serial number: %s\n\n", resp.SerialNumber)
	fmt.Fprintf(out, "Status: %s\n", statusMessage(resp.Status))

	if resp.Status == ocsp.Revoked {
		fmt.Fprintf(out, "Reason: %s\n", revocationReason(resp.RevocationReason))
		fmt.Fprintf(out, "Revoked at: %s\n", resp.RevokedAt)
	}

	fmt.Fprintf(out, "\nProduced at: %s\n", resp.ProducedAt)
	fmt.Fprintf(out, "This update: %s\n", resp.ThisUpdate)
	fmt.Fprintf(out, "Next update: %s\n", resp.NextUpdate)
}

var (
	statusMessages = map[int]string{
		ocsp.Good:         "Good",
		ocsp.Revoked:      "Revoked",
		ocsp.ServerFailed: "Server failed",
		ocsp.Unknown:      "Unknown",
	}
	revocationReasonMessages = map[int]string{
		ocsp.Unspecified:          "Unspecified",
		ocsp.KeyCompromise:        "Key compromise",
		ocsp.CACompromise:         "CA compromise",
		ocsp.AffiliationChanged:   "Affiliation changed",
		ocsp.Superseded:           "Superseded",
		ocsp.CessationOfOperation: "Cessation of operation",
		ocsp.CertificateHold:      "Certificate hold",
		ocsp.RemoveFromCRL:        "Remove from CRL",
		ocsp.PrivilegeWithdrawn:   "Privilege withdrawn",
		ocsp.AACompromise:         "AA compromise",
	}
)

func statusMessage(code int) string {
	return statusMessages[code]
}

func revocationReason(code int) string {
	return revocationReasonMessages[code]
}
