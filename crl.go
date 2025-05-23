package main

import (
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"os"
)

func getCRLDistributionPoint(cert *x509.Certificate) (string, error) {
	points := cert.CRLDistributionPoints
	if len(points) == 0 {
		return "", errNoCRLDistributionPointsFound
	}

	return points[0], nil
}

func (c *Client) getCRL(url string) (*x509.RevocationList, error) {
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, err
	}

	defer func() {
		if cerr := resp.Body.Close(); err == nil {
			err = cerr
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// TODO: Check that list is not expired https://goo.gl/e52YPC
	return x509.ParseRevocationList(body)
}

func findCert(serialNumber *big.Int, crlList *x509.RevocationList) *x509.RevocationListEntry {
	for revoked := range crlList.RevokedCertificateEntries {
		revCert := crlList.RevokedCertificateEntries[revoked]

		if serialNumber.Cmp(revCert.SerialNumber) == 0 {
			return &revCert
		}
	}

	return nil
}

func (c *Client) CheckCertificateStatusCRL(cert *x509.Certificate) {
	st, err := c.GetCRLResponse(cert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}

	fmt.Print(st.String())
}

// GetCRLResponse returns the CRL status for the specified certificate.
func (c *Client) GetCRLResponse(cert *x509.Certificate) (*Status, error) {
	endpoint, err := getCRLDistributionPoint(cert)
	if err != nil {
		return nil, err
	}

	crlList, err := c.getCRL(endpoint)
	if err != nil {
		// TODO: return proper error, e.g. 'could not get crl'
		return nil, err
	}

	revCert := findCert(cert.SerialNumber, crlList)

	if revCert != nil {
		return &Status{
			SerialNumber: cert.SerialNumber,
			Status:       "Revoked",
			RevokedAt:    revCert.RevocationTime,
		}, nil
	}

	return &Status{
		SerialNumber: cert.SerialNumber,
		Status:       "Good",
	}, nil
}
