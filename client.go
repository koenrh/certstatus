package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

type Client struct {
	httpClient HTTPClient
	out        io.Writer
}

func NewClient(httpClient HTTPClient, out io.Writer) *Client {
	client := &Client{}
	client.httpClient = httpClient
	client.out = out

	return client
}

func (c *Client) GetIssuerCertificate(cert *x509.Certificate) (*x509.Certificate, error) {
	var (
		issCert *x509.Certificate
	)

	for _, url := range cert.IssuingCertificateURL {
		resp, err := c.httpClient.Get(url)
		if err != nil {
			continue
		}

		if err != nil {
			return nil, errFailedToGetResource
		}

		defer func() {
			if cerr := resp.Body.Close(); err == nil {
				err = cerr
			}
		}()

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
	in, err := ioutil.ReadFile(path)

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
