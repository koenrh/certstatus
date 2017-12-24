package main

import (
	"math/big"
	"testing"
	"time"
)

func TestString(t *testing.T) {
	s := new(big.Int)
	s.SetString("17015245701990644280577643802745589798", 10)

	tt := time.Date(2017, 12, 20, 23, 59, 59, 0, time.UTC)
	st := &Status{
		SerialNumber: s,
		Status:       "Revoked",
		RevokedAt:    tt,
	}

	got := st.String()

	expected := "Serial number: 17015245701990644280577643802745589798\n\n" +
		"Status: Revoked\n" +
		"Revoked at: 2017-12-20 23:59:59 +0000 UTC\n"

	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}
