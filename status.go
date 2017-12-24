package main

import (
	"bytes"
	"fmt"
	"math/big"
	"time"
)

// Status holds the (revocation) status for a certificate
type Status struct {
	SerialNumber *big.Int
	Status       string
	Reason       string
	RevokedAt    time.Time
}

func (s Status) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString(fmt.Sprintf("Serial number: %s\n\n", s.SerialNumber))
	buf.WriteString(fmt.Sprintf("Status: %s\n", s.Status))

	if s.Reason != "" {
		buf.WriteString(fmt.Sprintf("Reason: %s\n", s.Reason))
	}

	if !s.RevokedAt.IsZero() {
		buf.WriteString(fmt.Sprintf("Revoked at: %s\n", s.RevokedAt.String()))
	}

	return buf.String()
}
