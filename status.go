package main

import (
	"fmt"
	"math/big"
	"strings"
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
	var b strings.Builder

	fmt.Fprintf(&b, "Serial number: %s\n\n", s.SerialNumber)
	fmt.Fprintf(&b, "Status: %s\n", s.Status)

	if s.Reason != "" {
		fmt.Fprintf(&b, "Reason: %s\n", s.Reason)
	}

	if !s.RevokedAt.IsZero() {
		fmt.Fprintf(&b, "Revoked at: %s\n", s.RevokedAt.String())
	}

	return b.String()
}
