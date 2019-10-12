package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"golang.org/x/crypto/ocsp"
)

func TestGetOCSPResponse(t *testing.T) {
	cert, err := readCertificate("./testdata/twitter.pem")
	if err != nil {
		t.Fatal("Could not read test certificate.")
	}

	issuer, err := readCertificate("./testdata/DigiCertSHA2ExtendedValidationServerCA.crt")
	if err != nil {
		t.Fatal("Could not read test issuer certificate.")
	}

	httpClient := &MockHTTPClient{}
	client := NewClient(httpClient, os.Stdout)
	resp, _ := client.GetOCSPResponse(cert, issuer)

	expected := "16190166165489431910151563605275097819"

	if resp.SerialNumber.String() != expected {
		t.Errorf("expected %q, got %q", expected, resp.SerialNumber.String())
	}
}

func TestGetOCSPServer(t *testing.T) {
	cert, _ := readCertificate("./testdata/certificate.pem")
	server, err := getOCSPServer(cert)

	if server != "http://ocsp.digicert.com" {
		t.Fatal(err)
	}
}

func TestPrintStatusResponse(t *testing.T) {
	rawResp, _ := ioutil.ReadFile("./testdata/twitter_ocsp_response_v1.der")
	resp, _ := ocsp.ParseResponse(rawResp, nil)

	out := new(bytes.Buffer) // capture output

	expected := "Serial number: 16190166165489431910151563605275097819\n\n" +
		"Status: Good\n\n" +
		"Produced at: 2017-12-23 06:30:33 +0000 UTC\n" +
		"This update: 2017-12-23 06:30:33 +0000 UTC\n" +
		"Next update: 2017-12-30 05:45:33 +0000 UTC\n"

	httpClient := &MockHTTPClient{}
	client := NewClient(httpClient, out)

	client.printStatusResponse(resp)

	got := out.String()
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestPrintStatusResponseRevoked(t *testing.T) {
	rawResp, _ := ioutil.ReadFile("./testdata/cisco_ocsp_response_revoked.der")
	resp, _ := ocsp.ParseResponse(rawResp, nil)

	out := new(bytes.Buffer) // capture output

	expected := "Serial number: 582831098329266023459877175593458587837818271346\n\n" +
		"Status: Revoked\n" +
		"Reason: Key compromise\n" +
		"Revoked at: 2017-06-18 17:57:00 +0000 UTC\n\n" +
		"Produced at: 2017-12-23 16:24:32 +0000 UTC\n" +
		"This update: 2017-12-23 16:24:32 +0000 UTC\n" +
		"Next update: 2017-12-25 16:24:32 +0000 UTC\n"

	httpClient := &MockHTTPClient{}
	client := NewClient(httpClient, out)
	client.printStatusResponse(resp)

	got := out.String()
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
