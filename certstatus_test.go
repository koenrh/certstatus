package main

import (
	"bytes"
	"errors"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
)

type MockHttpClient struct{}

func (m *MockHttpClient) Get(url string) (*http.Response, error) {
	var dat []byte

	if url == "http://cacerts.digicert.com/DigiCertSHA2SecureServerCA.crt" {
		dat, _ = ioutil.ReadFile("./testdata/issuer.pem")
	} else if url == "http://cacerts.digicert.com/DigiCertSHA2ExtendedValidationServerCA.crt" {
		dat, _ = ioutil.ReadFile("./testdata/DigiCertSHA2ExtendedValidationServerCA.pem")
	}

	response := &http.Response{
		Body: ioutil.NopCloser(bytes.NewBuffer(dat)),
	}
	return response, nil
}

func (m *MockHttpClient) Do(r *http.Request) (*http.Response, error) {
	if r.URL.String() == "http://ocsp.digicert.com" {
		ocspResponseBytes, _ := ioutil.ReadFile("./testdata/twitter_ocsp_response_v1.der")
		response := &http.Response{
			Body: ioutil.NopCloser(bytes.NewBuffer(ocspResponseBytes)),
		}
		return response, nil
	}

	return nil, errors.New("Unrecognised URL: " + "")
}

func TestMainWithArguments(t *testing.T) {
	client = &MockHttpClient{}
	os.Args = []string{
		"certstatus",
		"./testdata/twitter.pem",
	}
	main()
}

func TestPrintCertificateStatus(t *testing.T) {
	path := "./testdata/twitter.pem"
	client := &MockHttpClient{}

	printCertificateStatus(client, path)
}

func TestGetOCSPResponse(t *testing.T) {
	cert, err := readCertificate("./testdata/twitter.pem")
	if err != nil {
		t.Fatal("Could not read test certificate.")
	}

	issuer, err := readCertificate("./testdata/DigiCertSHA2ExtendedValidationServerCA.pem")
	if err != nil {
		t.Fatal("Could not read test issuer certificate.")
	}

	client := &MockHttpClient{}
	resp, _ := getOCSPResponse(client, cert, issuer)

	expected := "16190166165489431910151563605275097819"

	if resp.SerialNumber.String() != expected {
		t.Errorf("expected %q, got %q", expected, resp.SerialNumber.String())
	}
}

func TestGetIssuerCert(t *testing.T) {
	cert, err := readCertificate("./testdata/certificate.pem")
	if err != nil {
		t.Fatal(err)
	}

	client := &MockHttpClient{}
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

func TestCertificateFromBytesNoCertificate(t *testing.T) {
	in, _ := ioutil.ReadFile("./testdata/private_key.pem")
	_, err := certificateFromBytes(in)
	if err == nil {
		t.Fatal("should return error")
	}
}

func TestPrintStatusResponse(t *testing.T) {
	ocsp_der, _ := ioutil.ReadFile("./testdata/twitter_ocsp_response_v1.der")
	resp, _ := ocsp.ParseResponse(ocsp_der, nil)

	out = new(bytes.Buffer) // capture output

	expected := "Serial number: 16190166165489431910151563605275097819\n\n" +
		"Status: Good\n\n" +
		"Produced at: 2017-12-23 06:30:33 +0000 UTC\n" +
		"This update: 2017-12-23 06:30:33 +0000 UTC\n" +
		"Next update: 2017-12-30 05:45:33 +0000 UTC\n"

	printStatusResponse(resp)

	got := out.(*bytes.Buffer).String()
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestPrintStatusResponseRevoked(t *testing.T) {
	ocsp_der, _ := ioutil.ReadFile("./testdata/cisco_ocsp_response_revoked.der")
	resp, _ := ocsp.ParseResponse(ocsp_der, nil)

	out = new(bytes.Buffer) // capture output

	expected := "Serial number: 582831098329266023459877175593458587837818271346\n\n" +
		"Status: Revoked\n" +
		"Reason: Key compromise\n" +
		"Revoked at: 2017-06-18 17:57:00 +0000 UTC\n\n" +
		"Produced at: 2017-12-23 16:24:32 +0000 UTC\n" +
		"This update: 2017-12-23 16:24:32 +0000 UTC\n" +
		"Next update: 2017-12-25 16:24:32 +0000 UTC\n"

	printStatusResponse(resp)

	got := out.(*bytes.Buffer).String()
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestStatusMessage(t *testing.T) {
	status := statusMessage(ocsp.Good)
	expected := "Good"

	if status != expected {
		t.Errorf("expected %q, got %q", expected, status)
	}
}

func TestRevocationReason(t *testing.T) {
	reason := revocationReason(ocsp.KeyCompromise)
	expected := "Key compromise"

	if reason != expected {
		t.Errorf("expected %q, got %q", expected, reason)
	}
}
