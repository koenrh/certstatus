# Certificate status

[![Build Status](https://travis-ci.org/koenrh/certstatus.svg?branch=master)](https://travis-ci.org/koenrh/certstatus)

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

```
$ certstatus certificate.pem

Serial number: 56344244886667875955436183757038019206

Status: Revoked
Reason: Unspecified
Revoked at: 2017-07-04 18:08:16 +0000 UTC

Produced at: 2017-07-11 10:25:44 +0000 UTC
This update: 2017-07-11 10:25:43 +0000 UTC
Next update: 2017-07-15 10:35:43 +0000 UTC
```
