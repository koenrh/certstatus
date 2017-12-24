# Certificate status

[![Build Status](https://travis-ci.org/koenrh/certstatus.svg?branch=master)](https://travis-ci.org/koenrh/certstatus)
[![codecov](https://codecov.io/gh/koenrh/certstatus/branch/master/graph/badge.svg)](https://codecov.io/gh/koenrh/certstatus)

This is a little utility to obtain the (revocation) status of an X.509 certificate.

## Installation

Make sure you have set up your `$GOPATH` correctly, and you have included
`$GOPATH/bin` in your `$PATH`, then run the following command.

```bash
go get -u github.com/koenrh/certstatus
```

## Usage

The only argument you need to provided is the path to an X.509 certificate in
PEM-encoded format.

```bash
# OCSP
$ certstatus ocsp certificate.pem

Serial number: 582831098329266023459877175593458587837818271346

Status: Revoked
Reason: Key compromise
Revoked at: 2017-06-18 17:57:00 +0000 UTC

Produced at: 2017-12-24 18:22:40 +0000 UTC
This update: 2017-12-24 18:22:40 +0000 UTC
Next update: 2017-12-26 18:22:40 +0000 UTC

# CRL
$ certstatus crl certificate.pem
Serial number: 582831098329266023459877175593458587837818271346

Status: Revoked
Revoked at: 2017-06-18 17:57:00 +0000 UTC
```
