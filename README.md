# acme-client-operator

## Description

ACME Client Operator is a placeholder charm that contains the `acme_client` library.
The library contains a base charm implements the provider side of the `tls-certificates-interface`
to provide signed certificates from an ACME servers, using LEGO
(https://go-acme.github.io/lego).
It should be used as a base for charms that need to provide TLS certificates.

## Usage

While it is possible to deploy this charm, it is essentially a no-op, and not what this charm was designed for.
The charm should be used to access the `acme_client` library.

To get started using the library, you need to fetch the library using `charmcraft`.
```shell
charmcraft fetch-lib charms.acme_client_operator.v0.acme_client
```
You will also need to add the following library to the charm's `requirements.txt` file:
- jsonschema
- cryptography
