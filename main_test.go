package main

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type MockHTTPClient struct{}

func (m *MockHTTPClient) Get(url2 string) (*http.Response, error) {
	u, _ := url.Parse(url2)
	p := filepath.Clean(u.Path)
	dat, _ := ioutil.ReadFile("./testdata" + p)

	response := &http.Response{
		Body: ioutil.NopCloser(bytes.NewBuffer(dat)),
	}
	return response, nil
}

func (m *MockHTTPClient) Do(r *http.Request) (*http.Response, error) {
	if r.URL.String() == "http://ocsp.digicert.com" {
		ocspResponseBytes, _ := ioutil.ReadFile("./testdata/twitter_ocsp_response_v1.der")
		response := &http.Response{
			Body: ioutil.NopCloser(bytes.NewBuffer(ocspResponseBytes)),
		}
		return response, nil
	}

	return nil, errors.New("Unrecognised URL: " + "")
}

func TestMainOCSP(t *testing.T) {
	out = new(bytes.Buffer) // capture output

	client = &MockHTTPClient{}
	os.Args = []string{
		"certstatus",
		"ocsp",
		"./testdata/twitter.pem",
	}
	main()

	expected := "Status: Good"

	got := out.(*bytes.Buffer).String()
	if !strings.Contains(got, expected) {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestGetIssuerCert(t *testing.T) {
	cert, err := readCertificate("./testdata/certificate.pem")
	if err != nil {
		t.Fatal(err)
	}

	client := &MockHTTPClient{}
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

func TestCertificateFromBytesNoCertificate(t *testing.T) {
	in, _ := ioutil.ReadFile("./testdata/private_key.pem")
	_, err := certificateFromBytes(in)
	if err == nil {
		t.Fatal("should return error")
	}
}
