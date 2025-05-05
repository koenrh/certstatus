package main

import (
	"bytes"
	"fmt"
	"math/big"
	"time"
)

// Status holds the (revocation) status for a certificate.
type Status struct {
	SerialNumber *big.Int
	Status       string
	Reason       string
	RevokedAt    time.Time
}

func (s Status) String() string {
	buf := new(bytes.Buffer)

	fmt.Fprintf(buf, "Serial number: %s\n\n", s.SerialNumber)
	fmt.Fprintf(buf, "Status: %s\n", s.Status)

	if s.Reason != "" {
		fmt.Fprintf(buf, "Reason: %s\n", s.Reason)
	}

	if !s.RevokedAt.IsZero() {
		fmt.Fprintf(buf, "Revoked at: %s\n", s.RevokedAt.String())
	}

	return buf.String()
}
