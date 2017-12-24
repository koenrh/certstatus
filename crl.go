package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"math/big"
)

func getCRLDistributionPoint(cert *x509.Certificate) (string, error) {
	points := cert.CRLDistributionPoints
	if len(points) == 0 {
		return "", errNoCRLDistributionPointsFound
	}
	return points[0], nil
}

func getCRL(url string) (*pkix.CertificateList, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// TODO: Check that list is not expired https://goo.gl/e52YPC
	return x509.ParseCRL(body)
}

func findCert(serialNumber *big.Int, crlList *pkix.CertificateList) *pkix.RevokedCertificate {
	for revoked := range crlList.TBSCertList.RevokedCertificates {
		revCert := crlList.TBSCertList.RevokedCertificates[revoked]

		if serialNumber.Cmp(revCert.SerialNumber) == 0 {
			return &revCert
		}
	}

	return nil
}

func GetCRLResponse(client HTTPClient, cert *x509.Certificate) (*Status, error) {
	endpoint, err := getCRLDistributionPoint(cert)
	if err != nil {
		return nil, err
	}

	crlList, err := getCRL(endpoint)

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
