package main

import (
	"crypto/x509"
	"io/ioutil"
	"math/big"
	"testing"
)

func TestGetDistributionPoint(t *testing.T) {
	cert, _ := readCertificate("./testdata/certificate.pem")
	server, _ := getCRLDistributionPoint(cert)

	expected := "http://crl3.digicert.com/ssca-sha2-g3.crl"

	if server != expected {
		t.Errorf("expected %q, got %q", expected, server)
	}
}

func TestGetDestributionPointFromCertWithoutCRL(t *testing.T) {
	cert, _ := readCertificate("./testdata/cloudflare_origin_ca_rsa_root.crt")
	server, _ := getCRLDistributionPoint(cert)

	expected := ""

	if server != expected {
		t.Errorf("expected %q, got %q", expected, server)
	}
}

func TestFindCert(t *testing.T) {
	// NOTE: DigiCert SHA2 Extended Validation Server CA CRL
	crl, _ := ioutil.ReadFile("./testdata/sha2-ev-server-g2.crl")
	resp, err := x509.ParseCRL(crl)
	if err != nil {
		t.Fatal(err)
	}

	// Serial belongs to https://censys.io/certificates/39e31c9f5913e4ed68c9582de80c8be4689608f622075d0c81b6fe52dfe2db82
	s := new(big.Int)
	s.SetString("17015245701990644280577643802745589798", 10)

	test := findCert(s, resp)

	if test == nil {
		t.Errorf("expected to find revoked certificate with serial number %q", s.String())
	}
}

func TestFindNonExistingRevokedCert(t *testing.T) {
	// NOTE: DigiCert SHA2 Extended Validation Server CA CRL
	crl, _ := ioutil.ReadFile("./testdata/sha2-ev-server-g2.crl")
	resp, err := x509.ParseCRL(crl)
	if err != nil {
		t.Fatal(err)
	}

	test := findCert(big.NewInt(0), resp)

	if test != nil {
		t.Error("did not expect to find a revoked certificate")
	}
}

func TestGetCRLResponse(t *testing.T) {
	client = &MockHttpClient{}
	cert, err := readCertificate("./testdata/cisco_revoked.pem")

	if err != nil {
		t.Fatal(err)
	}

	st, err := GetCRLResponse(client, cert)

	if err != nil {
		t.Fatal(err)
	}

	expected := "Revoked"
	if st.Status != expected {
		t.Errorf("expected %q, got %q", expected, st.Status)
	}
}

func TestGetCRLResponseNotRevoked(t *testing.T) {
	client = &MockHttpClient{}
	cert, err := readCertificate("./testdata/twitter.pem")

	if err != nil {
		t.Fatal(err)
	}

	st, err := GetCRLResponse(client, cert)

	if err != nil {
		t.Fatal(err)
	}

	expected := "Good"
	if st.Status != expected {
		t.Errorf("expected %q, got %q", expected, st.Status)
	}
}
