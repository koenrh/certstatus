package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

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
