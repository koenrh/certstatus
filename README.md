# Certificate status

This is a little utility to look up the status of a certificate using OCSP.

## Installation

```bash
go get -u github.com/koenrh/certstatus
```

## Usage

You only need to provide the PEM-encoded certificate.

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
