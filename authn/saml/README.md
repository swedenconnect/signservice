![Logo](../../docs/images/sweden-connect.png)


# signservice/authn/saml

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-authn-saml/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-authn-saml)

-----

## About

The `signservice-authn-saml` module contains authentication handler implementations for the SAML WebSSO profile.
Currently, two implementations exists, the [DefaultSamlAuthenticationHandler](#default-saml-authentication-handler)
that is a generic SAML SP implementation and the [SwedenConnectSamlAuthenticationHandler](#sweden-connect-saml-authentication-handler) that is a SAML implementation that follows the [Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/) specifications.

Both implementations inherit from the abstract base class [AbstractSamlAuthenticationHandler](https://github.com/swedenconnect/signservice/blob/main/authn/saml/src/main/java/se/swedenconnect/signservice/authn/saml/AbstractSamlAuthenticationHandler.java). This class may be used to construct your own SAML authentication handler
suitable to your specific SAML needs. See [Making your own SAML handler](#making-your-own-saml-handler).


<a name="default-saml-authentication-handler"></a>
### DefaultSamlAuthenticationHandler

The [DefaultSamlAuthenticationHandler](https://github.com/swedenconnect/signservice/blob/main/authn/saml/src/main/java/se/swedenconnect/signservice/authn/saml/DefaultSamlAuthenticationHandler.java) makes no assumptions of a specific
SAML dialect. It implements SAML support for a generic WebSSO SAML SP.

See [Configuration](#configuration) below for how to configure the handler.

<a name="sweden-connect-saml-authentication-handler"></a>
### SwedenConnectSamlAuthenticationHandler

The [SwedenConnectSamlAuthenticationHandler](https://github.com/swedenconnect/signservice/blob/main/authn/saml/src/main/java/se/swedenconnect/signservice/authn/saml/SwedenConnectSamlAuthenticationHandler.java) implements a SAML SP 
according to the [Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/) and supports features
such as:

- The [SignMessage](https://docs.swedenconnect.se/technical-framework/latest/09_-_DSS_Extension_for_Federated_Signing_Services.html#element-signmessage) SAML extension enabling the transfer of
the SignRequest `SignMessage` to the Identity Provider. The IdP can then display a signature message for the
user when he or she authenticates for signature. 

- The [SAD](https://docs.swedenconnect.se/technical-framework/latest/13_-_Signature_Activation_Protocol.html) SAML extension. The function of the Signature Activation Protocol (and Signature Activation Data) is to authenticate the
intent of a signer to sign a particular document, or collection of documents.

- The [RequestedPrincipalSelection](https://docs.swedenconnect.se/technical-framework/latest/14_-_Principal_Selection_in_SAML_Authentication_Requests.html) SAML extension. An extension that enables a SAML
SP to transfer information about the user it wishes to authenticate to the IdP. In a SignService scenario
the requested signer information is generally known. This extension makes it possible for the SignService SP
to inform the IdP about this identity before the actual authentication takes place.

See [Configuration](#configuration) below for how to configure the handler.

<a name="making-your-own-saml-handler"></a>
### Making your own SAML handler

We are aware that the SAML implementations provided out of the box may not suit exactly the SAML authentication
needs for every type of SAML-federation. Therefore, the [AbstractSamlAuthenticationHandler](https://github.com/swedenconnect/signservice/blob/main/authn/saml/src/main/java/se/swedenconnect/signservice/authn/saml/AbstractSamlAuthenticationHandler.java) may be extended to put together a customized SAML authentication handler.

In order to use the configuration system described in [Configuration of Handlers](https://github.com/swedenconnect/signservice/tree/main/core#configuration-of-handlers) and [SignService Configuration](https://docs.swedenconnect.se/signservice/configuration.html) the [SamlAuthenticationHandlerConfiguration](https://github.com/swedenconnect/signservice/blob/main/authn/saml/src/main/java/se/swedenconnect/signservice/authn/saml/config/SamlAuthenticationHandlerConfiguration.java) and [SamlAuthenticationHandlerFactory](https://github.com/swedenconnect/signservice/blob/main/authn/saml/src/main/java/se/swedenconnect/signservice/authn/saml/config/SamlAuthenticationHandlerFactory.java) also need to be overridden for your customization.

### Configuration

Both the [DefaultSamlAuthenticationHandler](https://github.com/swedenconnect/signservice/blob/main/authn/saml/src/main/java/se/swedenconnect/signservice/authn/saml/DefaultSamlAuthenticationHandler.java) and the [SwedenConnectSamlAuthenticationHandler](https://github.com/swedenconnect/signservice/blob/main/authn/saml/src/main/java/se/swedenconnect/signservice/authn/saml/SwedenConnectSamlAuthenticationHandler.java) handlers can be created
using the [SamlAuthenticationHandlerFactory](https://github.com/swedenconnect/signservice/blob/main/authn/saml/src/main/java/se/swedenconnect/signservice/authn/saml/config/SamlAuthenticationHandlerFactory.java) factory that uses
[SamlAuthenticationHandlerConfiguration](https://github.com/swedenconnect/signservice/blob/main/authn/saml/src/main/java/se/swedenconnect/signservice/authn/saml/config/SamlAuthenticationHandlerConfiguration.java) for configuration.

Below follows a description of [SamlAuthenticationHandlerConfiguration](https://github.com/swedenconnect/signservice/blob/main/authn/saml/src/main/java/se/swedenconnect/signservice/authn/saml/config/SamlAuthenticationHandlerConfiguration.java):

> Note: Kebab-case is used for property values. See the source code for the actual naming of configuration parameters (camel-case).

| Property | Description | Default value |
| :--- | :--- | :--- |
| `saml-type` | The type of SAML "dialect" used. The value of `sweden-connect` is used to create a [SwedenConnectSamlAuthenticationHandler](https://github.com/swedenconnect/signservice/blob/main/authn/saml/src/main/java/se/swedenconnect/signservice/authn/saml/SwedenConnectSamlAuthenticationHandler.java) handler and `default` creates [DefaultSamlAuthenticationHandler](https://github.com/swedenconnect/signservice/blob/main/authn/saml/src/main/java/se/swedenconnect/signservice/authn/saml/DefaultSamlAuthenticationHandler.java). | `default` |
| `entity-id` | The SAML entityID of the SAML SP for this handler. | Mandatory. No default value. |
| `default-credential.*` | The SAML SP default credential. Used if no specific credential is given for signing and/or encrypt/decrypt. See [CredentialConfiguration](https://docs.swedenconnect.se/signservice/configuration.html#credential-configuration). | - |
| `signature-credential.*` | The SAML SP signature credential. See [CredentialConfiguration](https://docs.swedenconnect.se/signservice/configuration.html#credential-configuration). | If not assigned, the `default-credential` will be used. If that is not set either an error is reported. |
| `decryption-credential.*` | The SAML SP decryption credential, i.e., the credential that the SP uses to decrypt encrypted SAML assertions. If the SAML setup (federation) does not require encrypted assertions, this setting is optional (`require-encrypted-assertions`). See [CredentialConfiguration](https://docs.swedenconnect.se/signservice/configuration.html#credential-configuration).| If not assigned, the `default-credential` will be used. If that is not set either an error is reported (if encryption is used in the SAML setup). |
| `sp-paths.*` | Configuration for the different paths that this SAML SP accepts requests on. See [SAML SP URL Configuration](#saml-sp-url-configuration) | Mandatory. No default value. |
| `metadata-provider.*` | Configuration for the provider of SAML metadata, i.e., the component that downloads federation SAML metadata and makes it available to the SAML handler. This setting is mutually exclusive with `metadata-provider-ref` below. See [Metadata Provider Configuration](#metadata-provider-configuration) below. | If not `metadata-provider-ref` is assigned this setting is mandatory. |
| `metadata-provider-ref` | A bean name referring to an already existing `MetadataProvider` bean that should be used for downloading SAML federation metadata (see [Common Beans Configuration](https://docs.swedenconnect.se/signservice/configuration.html#common-beans-configuration). This setting is mutually exclusive with `metadata-provider`  above. | If `metadata-provider` is not assigned this setting is mandatory. |
| `metadata.*` | Configuration for this SP's SAML metadata. See [Metadata Configuration](#metadata-configuration) below. | Mandatory. No default value. |
| `message-replay-checker` | The message replay checker ([MessageReplayChecker](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/storage/MessageReplayChecker.java)) object. Mutually exclusive with `message-replay-checker-ref` below. | - |
| `message-replay-checker-ref` | A bean name reference to a ([MessageReplayChecker](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/storage/MessageReplayChecker.java)) bean. Mutually exclusive with `message-replay-checker` above. Also see the configuration of the application setting `signservice.message-replay-checker-bean-name` in the [Application Configuration](https://docs.swedenconnect.se/signservice/configuration.html#application-configuration) section. | - |
| `sign-authn-requests` | Boolean telling whether SAML authentication requests should be signed. | `true` |
| `require-encrypted-assertions` | Boolean telling whether we require SAML assertions to be encrypted. | `true` |
| `require-signed-assertions` | Boolean telling whether we require SAML assertions to be signed. <br />Note that the response message is generally signed. | `false` |
| `preferred-binding` | Tells which binding that should be preferred when sending the authentication request. Possible values are `redirect` and `post`. | `redirect` |
| `sad-request` | (Sweden Connect only) Value that tells under which circumstances a `SADRequest` extension is included in the authentication request. Possible values are: `DEFAULT`, which means that the `SADRequest` is included if this is explicitly requested (certificate type is QC_SSCD), `NEVER` and `ALWAYS` (provided that the IdP has declared support for the extension). | `DEFAULT` |

<a name="saml-sp-url-configuration"></a>
#### SAML SP URL Configuration

Under the configuration key `sp-paths` a set of URLs for the SAML SP are configured (see [SpUrlConfiguration](https://github.com/swedenconnect/signservice/blob/main/authn/saml/src/main/java/se/swedenconnect/signservice/authn/saml/config/SpUrlConfiguration.java)). These are:

| Property | Description | Default value |
| :--- | :--- | :--- |
| `base-url` | The SignService application base URL. Must not end with a slash. The base URL consists of the protocol, host and context path. | Mandatory. No default value. |
| `assertion-consumer-path` | The path to where the SP receives SAML responses. Relative `base-url`. Must begin with a `/`. | Mandatory. No default value. |
| `additional-assertion-consumer-path` | Optional additional path for receiving SAML responses. Relative to `base-url`. May be useful when testing and debugging. | - |
| `metadata-publishing-path` | The path to where the SP exposes its metadata. Relative to `base-url`. Must begin with a `/`. | Mandatory. No default value. |

<a name="metadata-provider-configuration"></a>
#### Metadata Provider Configuration

The [MetadataProviderConfiguration](https://github.com/swedenconnect/signservice/blob/main/authn/saml/src/main/java/se/swedenconnect/signservice/authn/saml/config/MetadataProviderConfiguration.java) class is used to configure how we download SAML metadata. The settings are:

| Property | Description | Default value |
| :--- | :--- | :--- |
| `validation-certificate` | The certificate used to validate the signature on downloaded metadata. | Optional. If no certificate is supplied no signature validation is performed. This is strongly discouraged for production systems. |
| `url` | The URL from where metadata is downloaded. Mutually exclusive with `file` below. | - |
| `file` | A full path to locally stored metadata. Mutually exclusive with `url` above. | - |
| `backup-location` | Optional property. If `url` is assigned, this setting points to a backup file where the downloaded data should be saved. If the `mdq` flag has been set, this property should point to a directory and not a file. | - |
| `mdq` | Optional property. If a metadata URL has been configured, setting this flag means that the metadata [MDQ protocol](https://www.ietf.org/id/draft-young-md-query-17.html) is used. | `false` |
| `http-proxy.*` | An optional HTTP proxy configuration. Should be assigned if the service is deployed behind a HTTP proxy. For settings see below. | . 
| `additional[]` | A list of additional metadata providers. Using this feature a chained metadata provider will be created where several sources of metadata will be used. | An empty list. |

The HTTP Proxy is configured using the following settings:

| Property | Description |
| :--- | :--- |
| `host` | The proxy host (mandatory) |
| `port` | The proxy port (mandatory) |
| `user-name` | The proxy user name (optional) |
| `password` | The proxy password (optional) |


<a name="metadata-configuration"></a>
#### Metadata Configuration

The [MetadataConfiguration](https://github.com/swedenconnect/signservice/blob/main/authn/saml/src/main/java/se/swedenconnect/signservice/authn/saml/config/MetadataConfiguration.java) class represents the configuration of how
the SAML SP metadata is created.

> TODO: Add table of all settings ...

-----

Copyright &copy; 2022-2023, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
