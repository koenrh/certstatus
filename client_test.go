package main

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestGetIssuerCert(t *testing.T) {
	cert, err := readCertificate("./testdata/certificate.pem")
	if err != nil {
		t.Fatal(err)
	}

	httpClient := &MockHTTPClient{}
	client := NewClient(httpClient, os.Stdout)

	if err != nil {
		t.Fatal(err)
	}

	issCert, err := client.GetIssuerCertificate(cert)

	if err != nil {
		t.Fatal(err)
	}

	if issCert.Issuer.CommonName != "DigiCert Global Root CA" {
		t.Fatal(issCert.Issuer.CommonName)
	}
}

func TestReadCertificate(t *testing.T) {
	_, err := readCertificate("./testdata/certificate.pem")
	if err != nil {
		t.Fatal(err)
	}
}

func TestCertificateFromBytesNoCertificate(t *testing.T) {
	in, _ := ioutil.ReadFile("./testdata/private_key.pem")
	_, err := certificateFromBytes(in)

	if err == nil {
		t.Fatal("should return error")
	}
}
