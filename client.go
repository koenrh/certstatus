package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

type Client struct {
	httpClient HTTPClient
	out        io.Writer
}

func NewClient(httpClient HTTPClient, out io.Writer) *Client {
	return &Client{httpClient: httpClient, out: out}
}

func (c *Client) GetIssuerCertificate(cert *x509.Certificate) (*x509.Certificate, error) {
	var issCert *x509.Certificate

	for _, url := range cert.IssuingCertificateURL {
		resp, err := c.httpClient.Get(url)
		if err != nil {
			continue
		}

		in, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
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
	in, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errFailedToReadCertificate, err)
	}

	cert, err := certificateFromBytes(in)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errFailedToReadCertificate, err)
	}

	return cert, nil
}
