![Logo](../docs/images/sweden-connect.png)


# signservice/signhandler

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-signhandler/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-signhandler)

-----

## About

The `signhandler` directory contains code for implementing the [SignatureHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/signature/SignatureHandler.java)
interface. This provides the functionality to generate user signatures using the signer's credentials.

### Configuration

The [DefaultSignatureHandler](https://github.com/swedenconnect/signservice/blob/main/signhandler/src/main/java/se/swedenconnect/signservice/signature/impl/DefaultSignatureHandler.java)
provides a default implementation capable of handling XML and PDF signatures in standard as well as ETSI baseline (BES) profile formats.

The [DefaultSignatureHandlerConfiguration](https://github.com/swedenconnect/signservice/blob/main/signhandler/src/main/java/se/swedenconnect/signservice/signature/config/DefaultSignatureHandlerConfiguration.java)
describes the configuration for a [DefaultSignatureHandler](https://github.com/swedenconnect/signservice/blob/main/signhandler/src/main/java/se/swedenconnect/signservice/signature/impl/DefaultSignatureHandler.java)
instance.

| Property            | Description                                                                                                                         |
|:--------------------|:------------------------------------------------------------------------------------------------------------------------------------|
| `algorithmRegistry` | The algorithm registry. If not assigned, the registry given from a call to `AlgorithmRegistrySingleton#getInstance()` will be used. |
| `signerProvider`    | The signer provider. If not assigned, `DefaultSignServiceSignerProvider` will be used.                                                |
| `tbsProcessors`     | A list of configured To-Be-Signed (TBS) data processors for different signature types.                                              |

The [TBSDataProcessorConfiguration](https://github.com/swedenconnect/signservice/blob/main/signhandler/src/main/java/se/swedenconnect/signservice/signature/config/TBSDataProcessorConfiguration.java)
describes the configuration for each instance of a TBS data processor.

| Property                           | Description                                                                                                                                                                         |
|:-----------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `type`                             | The type of the processor. Supported values are "xml" and "pdf".                                                                                                                    | 
| `strictProcessing`                 | Boolean, defining if processing of input data is strict or applies the Postel's robustness principle. Default `false`.                                                              |
| `includeIssuerSerial`              | Boolean, defining if issuerSerial should be included in signatures that include a reference to the signer's certificate, as required by the ETSI baseline profile. Default `false`. |
| `supportedProcessingRules`         | Otpional List of processing rule identifiers that governs the processing of data in the signing process.                                                                            |
| `defaultCanonicalizationAlgorithm` | Otpional canonicalization algorithm. Relevant only if type is "xml". Specifies the default canonicalization algorithm to use (default `http://www.w3.org/2001/10/xml-exc-c14n#`).   |

-----

Copyright &copy; 2022-2023, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
