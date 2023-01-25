![Logo](../../docs/images/sweden-connect.png)


# signservice/keycert/cmc

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-keycert-cmc/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-keycert-cmc)

-----

## About

The `cmc` module provides an implementation of the [KeyAndCertificateHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/certificate/KeyAndCertificateHandler.java) API
where issuance of signer certificates is managed by an external CA using the [Certificate Management over CMS](https://www.rfc-editor.org/rfc/rfc5272.html) (CMC) protocol.

The serves a scenario where the sign service acts as an RA that specifies the identity and certificate content of issued certificates, and where
the CA issues these certificates as ordered as long as they comply with defined policies and restrictions.


### Configuration

The CMC based key and certificate handler incorporates the [base configuration](https://github.com/swedenconnect/signservice/tree/main/keycert/base)
parameters from the `base` module

The [CMCKeyAndCertificateHandlerConfiguration](https://github.com/swedenconnect/signservice/blob/main/keycert/cmc/src/main/java/se/swedenconnect/signservice/certificate/cmc/config/CMCKeyAndCertificateHandlerConfiguration.java)
configuration data class describes additional configuration parameters for the CMC based key and certificate handler:

| Field                      | Description                                                                                                                                                                                                  |
|:---------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `cmcRequestUrl`            | The URL for sending CMC requests                                                                                                                                                                             |
| `cmcClientCredential`      | The CMC client credential used to sign CMC requests                                                                                                                                                          |
| `cmcSigningAlgorithm`      | The signing algorithm used to sign CMC requests. Defaults to `XMLSignature#ALGO_ID_SIGNATURE_RSA_SHA256` or  `XMLSignature#ALGO_ID_SIGNATURE_ECDSA_SHA256` depending on the type of client credentials used. |
| `cmcResponderCertificate`  | The CMC responder certificate used to validate CMC responses from the CA.                                                                                                                                    |
| `remoteCaInfo`             | Information about the remote CA as described below                                                                                                                                                           |
| `cmcClientProxy`           | Optional http proxy configuration for CMC requests. This parameter is null if not proxy is used                                                                                                              |

The [RemoteCaInformation](https://github.com/swedenconnect/signservice/blob/main/keycert/cmc/src/main/java/se/swedenconnect/signservice/certificate/cmc/ca/RemoteCaInformation.java)
configuration data class specifies the following information about the remote CA:

| Field                | Description                                                                            |
|:---------------------|----------------------------------------------------------------------------------------|
| `caCertificateChain` | The certificate chain for the issuing certificate of the CA                            |
| `caAlgorithm`        | The algorithm used by the CA to sign certificates                                      |
| `crlDpUrls`          | List of CRL distribution point URL:s to be included in certificates issued by this CA. |
| `ocspResponderUrl`   | OCSP responder URL to be included in certificates issued by this CA.                   |

The `cmcClientProxy` configuration data specifies the following information about an optional http proxy for CMC requests:

| Field      | Description                  |
|:-----------|------------------------------|
| `host`     | The host name of the proxy   |
| `port`     | The port number of the proxy |
| `userName` | Optional user name           |
| `password` | Optional passwrod            |


-----

Copyright &copy; 2022-2023, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
