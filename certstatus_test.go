package main

import (
	"errors"
	"io/ioutil"
	"testing"
)

type stubHTTPClient struct{}

func (stubHTTPClient) get(url string) ([]byte, error) {
	if url == "http://cacerts.digicert.com/DigiCertSHA2SecureServerCA.crt" {
		return ioutil.ReadFile("./testdata/issuer.pem")
	}

	return nil, errors.New("Unrecognised URL: " + url)
}

func TestGetIssuerCert(t *testing.T) {
	cert, err := readCertificate("./testdata/certificate.pem")
	if err != nil {
		t.Fatal(err)
	}

	client := &stubHTTPClient{}
	issCert, err := getIssuerCertificate(client, cert)
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

func TestGetOCSPServer(t *testing.T) {
	cert, _ := readCertificate("./testdata/certificate.pem")
	server, err := getOCSPServer(cert)
	if server != "http://ocsp.digicert.com" {
		t.Fatal(err)
	}
}

func TestDownloadCertificateUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err := downloadCertificate(server.URL)

	if err.Error() != "response code is not OK" {
		t.Fatalf("wrong error message: %s", err.Error())
	}
}

func TestCertificateFromBytesNoCertificate(t *testing.T) {
	in, _ := ioutil.ReadFile("./testdata/private_key.pem")
	_, err := certificateFromBytes(in)
	if err == nil {
		t.Fatal("should return error")
	}
}
