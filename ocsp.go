package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"golang.org/x/crypto/ocsp"
)

func getOCSPServer(cert *x509.Certificate) (string, error) {
	ocspServers := cert.OCSPServer
	if len(ocspServers) == 0 {
		return "", errNoOCSPServersFound
	}

	return ocspServers[0], nil
}

func (c *Client) CheckCertificateStatusOCSP(cert *x509.Certificate) {
	issuer, err := c.GetIssuerCertificate(cert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}

	resp, err := c.GetOCSPResponse(cert, issuer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}

	c.printStatusResponse(resp)
}

func (c *Client) GetOCSPResponse(cert *x509.Certificate, issuer *x509.Certificate) (*ocsp.Response, error) {
	ocspServer, err := getOCSPServer(cert)
	if err != nil {
		return nil, err
	}

	options := ocsp.RequestOptions{Hash: crypto.SHA1}

	request, err := ocsp.CreateRequest(cert, issuer, &options)
	if err != nil {
		return nil, err
	}

	url, err := url.Parse(ocspServer)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", ocspServer, bytes.NewBuffer(request))
	if err != nil {
		return nil, err
	}

	req.Host = url.Hostname()
	req.Header.Set("content-type", "application/ocsp-request")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errFailedToFetchOCSPResponse
	}

	defer func() {
		if cerr := resp.Body.Close(); err == nil {
			err = cerr
		}
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	parsedResponse, err := ocsp.ParseResponseForCert(body, cert, issuer)
	if err != nil {
		return nil, err
	}

	return parsedResponse, nil
}

func (c *Client) printStatusResponse(resp *ocsp.Response) {
	fmt.Fprintf(c.out, "Serial number: %s\n\n", resp.SerialNumber)
	fmt.Fprintf(c.out, "Status: %s\n", statusMessage(resp.Status))

	if resp.Status == ocsp.Revoked {
		fmt.Fprintf(c.out, "Reason: %s\n", revocationReason(resp.RevocationReason))
		fmt.Fprintf(c.out, "Revoked at: %s\n", resp.RevokedAt)
	}

	fmt.Fprintf(c.out, "\nProduced at: %s\n", resp.ProducedAt)
	fmt.Fprintf(c.out, "This update: %s\n", resp.ThisUpdate)
	fmt.Fprintf(c.out, "Next update: %s\n", resp.NextUpdate)
}

func statusMessage(code int) string {
	statusMessages := map[int]string{
		ocsp.Good:         "Good",
		ocsp.Revoked:      "Revoked",
		ocsp.ServerFailed: "Server failed",
		ocsp.Unknown:      "Unknown",
	}

	return statusMessages[code]
}

func revocationReason(code int) string {
	revocationReasonMessages := map[int]string{
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

	return revocationReasonMessages[code]
}
