![Logo](../../docs/images/sweden-connect.png)

# signservice/keycert/base

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-keycert-base/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-keycert-base)

-----

## About

This base module provides common functions for implementations for the [KeyAndCertificateHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/certificate/KeyAndCertificateHandler.java) API.


### Configuration

This module provides the following common configuration classes for all KeyAndCertificateHandler instances:

 - [CredentialContainerConfiguration](https://github.com/swedenconnect/signservice/blob/main/keycert/base/src/main/java/se/swedenconnect/signservice/certificate/base/config/CredentialContainerConfiguration.java)
 - [AbstractKeyAndCertificateHandlerConfiguration](https://github.com/swedenconnect/signservice/blob/main/keycert/base/src/main/java/se/swedenconnect/signservice/certificate/base/config/AbstractKeyAndCertificateHandlerConfiguration.java)
   - DefaultValuePolicyCheckerConfiguration (Inner Class)
 - [CertificateProfileConfiguration](https://github.com/swedenconnect/signservice/blob/main/keycert/base/src/main/java/se/swedenconnect/signservice/certificate/base/config/CertificateProfileConfiguration.java)
 - [SigningKeyUsageDirective](https://github.com/swedenconnect/signservice/blob/main/keycert/base/src/main/java/se/swedenconnect/signservice/certificate/base/config/SigningKeyUsageDirective.java)
 

#### CredentialContainerConfiguration

The CredentialContainerConfiguration describes the configuration for the signer key provider used to generate the signing keys used to sign documents in the signature service.

| Field                  | Description                                                                                                                                                                                           |
|:-----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `hsmConfigurationFile` | A full path to the PKCS#11 configuration file. If not provided generation and use of software based keys will be effective.                                                                           | 
| `hsmPin`               | The PIN/password used to access the HSM slot if HSM is used.                                                                                                                                          |
| `securityProvider`     | The name of the crypto provider used to generate software based keys. This value is ignored if the `hsmConfigurationFile` property is set. If not provided, a default security provider will be used. |

#### AbstractKeyAndCertificateHandlerConfiguration

The AbstractKeyAndCertificateHandlerConfiguration class describes base configuration parameters common to all KeyAndCertificateHandler instances.

| Field                         | Description                                                                                                                                                                                                                                                                                                                                                |
|:------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `algorithmRegistry`           | Algorithm registry providing information about supported algorithms. If not assigned a default AlgorithmRegistry is used.                                                                                                                                                                                                                                  |
| `algorithmKeyType`            | A map specifying the key type for each supported algorithm type (primary EC and RSA algorithm types). See [KeyGenType](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/container/keytype/KeyGenType.java) for possible values. If not set, default key types will be set by the handler. |
| `keyProvider`                 | Configuration for the signature key provider (see CredentialContainerConfiguration configuration above).                                                                                                                                                                                                                                                   |
| `keyProviderRef`              | Reference to an existing PkiCredentialContainer bean to be used as the keyProvider for this handler.                                                                                                                                                                                                                                                       |
| `attributeMapper`             | Attribute mapper responsible for mapping authentication attributes/claims to certificate attributes. If not set, a default attribute mapper will be assigned.                                                                                                                                                                                              |
| `defaultValuePolicyChecker`   | Configuration for permitted default values used in attribute mapping if no value is provided by the identity provider. If no attribute mapper is set by the `attributeMapper` configuration parameter, then a `DefaultAttributeMapper` will be created based on this `defaultValuePolicyChecker` configuration.                                            |
| `caSupportedCertificateTypes` | A list of certificate types supported by this CA (Supported values: "`CertificateType.PKC`", "`CertificateType.QC`" and "`CertificateType.QC_SSCD`"                                                                                                                                                                                                        |
| `profileConfiguration`        | Configuration of the certificate profile used to determine the content of issued certificates.                                                                                                                                                                                                                                                             |
| `serviceName`                 | Service name placed in AuthnContextExtensions. If not set, the client ID will be used by default.                                                                                                                                                                                                                                                          |

#### DefaultValuePolicyCheckerConfiguration

The DefaultValuePolicyCheckerConfiguration has the following configuration data:

| Field           | Description                                                                                                                                                                                                                                                                                                                 |
|:----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `rules`         | A list of [DefaultValuePolicyCheckerConfig](https://github.com/swedenconnect/signservice/blob/main/keycert/base/src/main/java/se/swedenconnect/signservice/certificate/attributemapping/DefaultValuePolicyCheckerImpl.java) configuration data. Each object in the list holds configuration data for a particular attribute |
| `defaultReply`  | This defines the default reply (true or false) if a default value is allowed in cases where no rule is specified for a supplied item (attribute type and reference).                                                                                                                                                        |

DefaultValuePolicyCheckerConfig in DefaultValuePolicyCheckerConfiguration has the following configuration data:

| Field            | Description                                                                                                                                                                                                 |
|:-----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `attributeTyep`  | The certificate attribute type this attribute is mapped to, I.e `RDN` (Relative Distinguished Name), `SAN` (Subject Alternative Name) or `SDA` (Subject Directory Attribute)                                |
| `ref`            | The reference of the certificate attribute or subject alt name. For an attribute (`RDN` or `SDA`) this is the attribute OID string and for a SAN it is the index of the enumerated GeneralName types in SAN |
| `allowedValues`  | A list of allowed values. If null or empty, the `allowAnyValue` will determine if the value is OK                                                                                                           |
| `allowAnyValue`  | If allowedValues are null or empty, this field determines whether a default value assignment should be allowed.                                                                                             |

#### CertificateProfileConfiguration

The certificate profile configuration allows some control over the content in issued signer certificates:

| Field                      | Description                                                                                             |
|:---------------------------|---------------------------------------------------------------------------------------------------------|
| `policies`                 | A list of certificate Policy OIDs (String representation) that will be included in issued certificates. |
| `extendedKeyUsages`        | List of extended key usage object identifier values that will be included in issued certificates.       |
| `extendedKeyUsageCritical` | Determines if a present extended key usage extension is critical.                                       |
| `usageDirective`           | Optional settings for certificate key usage.                                                            |
| `keyUsageCritical`         | Determines if the present key usage extension is critical.                                              |
| `basicConstraintsCritical` | Determines if the present basic constraints extension is critical.                                      |

#### SigningKeyUsageDirective

The SigningKeyUsageDirective provides configuration data for the `usageDirective` parameter above:

| Field                   | Description                                                                                             |
|:------------------------|---------------------------------------------------------------------------------------------------------|
| `encrypt`               | Flag that marks the key usage for the signing key for encryption (as well as signing). Default `false`. |
| `excludeNonRepudiation` | Flag that marks that the key usage for the signing key should not include non-repudiation.              | 


-----

Copyright &copy; 2022, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
