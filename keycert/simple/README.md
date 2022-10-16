![Logo](../../docs/images/sweden-connect.png)


# signservice/keycert/simple

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-keycert-simple/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-keycert-simple)

-----

## About

The `simple` module provides a simple implementation of the [KeyAndCertificateHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/certificate/KeyAndCertificateHandler.java) API.
This implementation includes a local embedded CA (Certification Authority) for issuance of signer certificates.

The local embedded CA has the following limitations:

- Issued certificates are not stored. Once delivered to the signing process, certificates are deleted.
- Revocation of certificates is not supported. An empty revocation list is stored on disk


### Configuration

The simple key and certificate handler incorporates the base configuration parameters described here
:
> [base configuration](https://github.com/swedenconnect/signservice/tree/main/keycert/base)

The [SimpleKeyAndCertificateHandlerConfiguration](https://github.com/swedenconnect/signservice/blob/main/keycert/simple/src/main/java/se/swedenconnect/signservice/certificate/simple/config/SimpleKeyAndCertificateHandlerConfiguration.java)
describes additional configuration parameters for the simple key and certificate handler:

| Field                | Description                                                                                                                                                                          |
|:---------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `baseUrl`            | The application base URL for the signservice where this CA is deployed. Must not end with a slash. The base URL consists of the protocol, host and context path.                     |
| `caCredential`       | The CA credential (private key and certificate(s)) used by the CA when issuing certificates.                                                                                         |
| `caSigningAlgorithm` | The CA signing algorithm. Defaults to `XMLSignature#ALGO_ID_SIGNATURE_RSA_SHA256` or `XMLSignature#ALGO_ID_SIGNATURE_ECDSA_SHA256` depending on the type of client credentials used. |
| `certValidity`       | The validity for issued certificates. The default is 1 year.                                                                                                                         |
| `crlValidity`        | The validity for issued CRL:s. The default is 2 days.                                                                                                                                |
| `crlDpPath`          | The path to where CRL:s are exposed relative to `baseUrl`.                                                                                                                           |
| `crlDpUrl`           | A URL where the CRL is published. This option may be used if the CRL is published under a publicly available URL to allow validation of the signature certificate.                   |
| `crlFileLocation`    | Even though revocation is not supported we need to support an empty CRL. This property tells where to store thisCRL locally.                                                         |

> TODO

-----

Copyright &copy; 2022, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
