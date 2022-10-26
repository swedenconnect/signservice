![Logo](images/sweden-connect.png)

# Signature Service Configuration

This page helps you understand how to configure a SignService application. The settings documented here assume
that the configuration of a SignService application is made using properties, or Yaml-files. 

In order to get
the full, and even more detailed, picture, check each handler configuration. This is documented in each modules
README.md file, and the hierarchy starts at the [SignService GitHub root page](https://github.com/swedenconnect/signservice/blob/main/README.md).

> Note: All settings are given in "Kebab case" (words separated by dashes). However, "Camel case" will also work.

<a name="application-configuration"></a>
## Application Configuration

The documentation for the [signservice-config](https://github.com/swedenconnect/signservice/tree/main/config) module
describes how a SignService factory is set up and supplied with a configuration object in order to create a SignService
engine manager. This manager is the only bean a SignService application needs to use. All SignService logic is 
encapsulated in this object.

Below follows a description of the configuration object that is supplied to the SignService factory.

| Property | Description | Default value |
| :--- | :--- | :--- |
| `signservice.domain` | The domain under which the SignService is running. | Mandatory. No default value. |
| `signservice.base-url` | The "base URL" of the SignService, i.e., the protocol, domain and context path (if set to something other than '/'). Must not end with a '/'. | Mandatory. No default value. |
| `signservice.`<br />`default-sign-service-id` | The default SignService ID. May be overridden in engine configurations (see [Engine Configuration](#engine-configuration) below). | - |
| `signservice.default-credential.*` | Configuration for the SignService default credential that will be used for signing responses. By setting this, several engine configurations may share the same credential. See [Credential Configuration](#credential-configuration). | - |
| `signservice.common-beans.*` | The configuration for some handlers, and also some other beans, normally do not differ between different engines (clients). It is not very efficient if every engine instance instantiates their own beans (for handlers or other base components). Instead the engine configuration can point to an already existing bean. This configuration properties class defines the configuration for components that may be "common". See [Common Beans Configuration](#common-beans-configuration). <br /><br />**Note:** If your application should only serve one client (engine), there is no point in using this setting. | - |
| `signservice.`<br />`default-handler-config.*` | Shared, or default, configuration properties that may be merged into the engine configuration. The idea is to enter common values for the different handlers used in the engine configurations in order to avoid repeating the same configuration values. For example, a SAML-SP configuration may be identical between different clients except for its entityID and assertion consumer service URL. In these cases all engine configurations may all point at the same "default settings" and only configure what is unique for a given engine. See [Shared Handler Configuration](#shared-handler-configuration) below. <br /><br />**Note:** If your application should only serve one client (engine), there is no point in using this setting. | - |
| `signservice.system-audit.*` | Configuration for the system (application) audit logger. Note that each engine also has its own audit logger. The system audit logger logs entries that has to do with the actual application (start-up, shutdown, fatal errors, ...).<br />See [Audit Logger Configuration](#audit-logger-configuration) below.  | Mandatory. No default value. |
| `signservice.`<br />`session-handler-bean-name` | The name of the session handler bean ([SessionHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/session/SessionHandler.java)) that the application should use for maintaining sessions. | If no bean is specified a [DefaultSessionHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/session/impl/DefaultSessionHandler.java) object will be instantiated and used. | 
| `signservice.message-`<br />`replay-checker-bean-name` | Refers to a [MessageReplayChecker](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/storage/MessageReplayChecker.java) bean that will be used by the application to detect message replay attacks. | If no bean is specified a [DefaultMessageReplayChecker](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/storage/impl/DefaultMessageReplayChecker.java) instance will be created (it will use the below property to access a replay checker storage container).
| `signservice.replay-checker-`<br />`storage-container-bean-name` | Only relevant if `message-replay-checker-bean-name`  has not been set. In these cases a [DefaultMessageReplayChecker](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/storage/impl/DefaultMessageReplayChecker.java) will be created an supplied with a [ReplayCheckerStorageContainer](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/storage/impl/ReplayCheckerStorageContainer.java) instance. This setting refers to this bean. | If no bean is specified a [InMemoryReplayCheckerStorageContainer](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/storage/impl/InMemoryReplayCheckerStorageContainer.java) will be created. <br />This is not advisable in a distributed application setup (i.e., when several instances of the SignService application is running). |
| `signservice.engines[].*` | A list of engine configurations. Each engine configuration handles one SignService client.<br />See [Engine Configuration](#engine-configuration) below. | Mandatory. At least of engine configuration must be given. |


<a name="engine-configuration"></a>
### Engine Configuration

A SignService engine instance is running in a SignService application and is servicing the requests from one, and only one, SignService client. A SignService application is configured with one, or more engines.

In the SignService application above the engine configurations are prefixed using `signservice.engines[x]` where
`x` is the list order for the specific engine configuration.

| Property | Description | Default value |
| :--- | :--- | :--- |
| `name` | The name of this engine. It is recommended to use a name that refers to the client it is serving. This name will be used in log entries. | Mandatory. No default value. |
| `sign-service-id` | The ID that the SignService identifies itself as when processing requests for this engine. | If no value is given the `signservice.default-sign-service-id` (above) is used. |
| `credential` | The credential (key and certificate) that the SignService uses to sign SignResponse messages when processing requests for this engine.<br />See [Credential Configuration](#credential-configuration) | If no value is given the `signservice.default-credential` setting is used. |
| `processing-paths[]` | A list of processing paths for this engine. The paths are relative to the application's context path and must start with a `/ `. A processing path is typically the path on which the engine accepts SignRequest messages.<br /><br />**Note:** When configuring several engines make sure that the paths for the different engines are unique. The SignService engine manager that is responsible of dispatching incoming requests will hand a request over to the first engine whose processing paths match the incoming request. | Mandatory. At least one path is required. No default value. | 
| `client.client-id` | The unique client ID for the SignService client that this engine serves. | Mandatory. No default value. |
| `client.trusted-certificates[]` | A list of X.509 certificates that the engine "trusts" when it comes to verifying signatures on SignRequest messages from the client. | No default value. Depending on the protocol requirements, i.e., whether the SignService protocol requires requests to be signed or not, the setting may be mandatory. |
| `client.response-urls[]` | A list of registered URLs on which the client may received SignResponse messages. | No default value. Depending on the protocol requirements, i.e., whether the SignService protocol requires a pre-registered response URL or not, the setting may be mandatory. |
| `protocol.*` | SignService protocol configuration for this engine. See [Protocol Configuration](#protocol-configuration) below. | Mandatory. No default value. |
| `authn.*` | Authentication configuration for this engine. See [Authentication Configuration](#authentication-configuration) below. | Mandatory. No default value. |
| `sign.*` | Signature handler configuration for this engine. See [Signature Handler Configuration](#signature-handler-configuration) below. | Mandatory. No default value. |
| `cert.*` | Configuration for this engine's key and certificate handler, i.e., the handler that generates the signing key and signing certificate. See [Key and Certificate Handler Configuration](#key-and-certificate-handler-configuration) below. | Mandatory. No default value. |
| `audit.*` | Configuration for the engine (client) audit logger. This audit logger will log events that are specific for the client (for example successful and failed signature operations).<br />See [Audit Logger Configuration](#audit-logger-configuration) below.  | Mandatory. No default value. |

<a name="common-beans-configuration"></a>
### Common Beans Configuration

The configuration for some handlers, and also some other beans, normally do not differ between different engines
(clients). It is not very efficient if every engine instance instantiates their own beans (for handlers or other base
components). Instead the engine configuration can point to an already existing bean. This configuration properties
class defines the configuration for components that may be "common". 

The following configuration may appear under the `signservice.common-beans` property.

All settings have a property, `bean-name`, that tells under which name the common bean should be registered, and
how it should be loaded by references in the engine configuration.

| Property | Description |
| :--- | :--- |
| `protocol.*` | Configuration for a common protocol handler bean. See [Protocol Configuration](#protocol-configuration) below. |
| `sign.*` | Configuration for a common signature handler bean. See [Signature Handler Configuration](#signature-handler-configuration) below. |
| `key-provider.*` | The configuration for a [PkiCredentialContainer](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/container/PkiCredentialContainer.java) object that later may be referenced in a [Key and Certificate Handler Configuration](#key-and-certificate-handler-configuration). See [CredentialContainerConfiguration](https://github.com/swedenconnect/signservice/tree/main/keycert/base). |
| `cert.*` | Configuration for a common key and certificate handler bean. See [Key and Certificate Handler Configuration](#key-and-certificate-handler-configuration). |
| `saml.metadata-provider.*` | A signature service normally has the same SAML metadata provider for all of its clients, and a provider instance is pretty expensive to create, or rather, it spawns threads that download SAML metadata periodically. Having X clients doing the same task is completely unnecessary. Therefore it is possible to create a stand-alone `MetadataProvider` bean that is referenced by all the client SAML handlers. See [MetadataProviderConfiguration](https://github.com/swedenconnect/signservice/tree/main/authn/saml#metadata-provider-configuration). |


<a name="shared-handler-configuration"></a>
### Shared Handler Configuration

In SignService setups that has more than one engine (client) it is likely that the different engines are configured
with handlers that are unique for the engine (client) but still has many settings that are shared between the instances.

So, shared, or default, configuration properties can be used to avoid repeating configuration settings. For example, a SAML-SP configuration may be identical between different clients except for its entityID and assertion consumer service URL. In these cases all engine configurations may all point at the same "default settings" and only configure what is unique for a given engine. 

The following settings may be used as "shared settings". Note that these configurations are never mapped to handler
objects themselves, so a configuration does not have to be "complete".

| Property | Description |
| :--- | :--- |
| `protocol.*` | Shared SignService protocol configuration. See [Protocol Configuration](#protocol-configuration) below. |
| `authn.*` | Shared authentication configuration. See [Authentication Configuration](#authentication-configuration) below. |
| `sign.*` | Shared signature handler configuration. See [Signature Handler Configuration](#signature-handler-configuration) below. |
| `cert.*` | Shared configuration for a key and certificate handler. See [Key and Certificate Handler Configuration](#key-and-certificate-handler-configuration) below. |
| `audit.*` | Shared configuration for audit loggers. See [Audit Logger Configuration](#audit-logger-configuration) below.  |

<a name="handler-configuration"></a>
### Handler Configuration

A SignService engine is instantiated with a set of different handlers, one of each type. Handler configuration is
standardized and described in the documentation for the [signservice-core](https://github.com/swedenconnect/signservice/tree/main/core) module. 

**Note:** If [Shared Handler Configuration](#shared-handler-configuration) is used, a template configuration may be
referenced in the handler configuration using the setting `default-config-ref`. By including a reference using the
setting that follows after `signservice.default-handler-config`, for example `authn.saml`, these properties are
used for the handler configuration and we only have to configure common settings in one place, but still get our
own handler instance. See [Configuration Example](#configuration-example) below.

**Note 2:** If a customized handler, for a specific type, is to be used it is possible to tell the configuration system
to use another [HandlerFactory](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/core/config/HandlerFactory.java) that what is default by using the `factory-class`
property that points at the factory class for your customized handler. See [Configuration of Handlers](https://github.com/swedenconnect/signservice/tree/main/core#configuration-of-handlers).

Below follows the main configuration entry points for each type of handler.

<a name="audit-logger-configuration"></a>
#### Audit Logger Configuration

An [AuditLogger](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/audit/AuditLogger.java) instance is configured using the following configuration where one, and only one, setting should be supplied.

| Property | Description |
| :--- | :--- |
| `external.bean-name` | A bean name for an externally created handler bean. |
| `file.*` | File-based audit logging, see [FileAuditLogger](https://github.com/swedenconnect/signservice/tree/main/audit/base#fileauditlogger). |
| `log-system.*` | Audit-logging that uses an underlying log system, via Slf4j, to produce audit log entries. See [LogSystemAuditLogger](https://github.com/swedenconnect/signservice/tree/main/audit/base#log-system-audit-logger). |
| `callback.*` | Audit-logging that uses callbacks to a configured [AuditLoggerListener](https://github.com/swedenconnect/signservice/blob/main/audit/base/src/main/java/se/swedenconnect/signservice/audit/callback/AuditLoggerListener.java) object. See [CallbackAuditLogger](https://github.com/swedenconnect/signservice/tree/main/audit/base#callback-audit-logger). |
| `actuator.*` | For Spring Boot only. Uses Spring Boot's Actuator to publish audit log entries. See [ActuatorAuditLogger](https://github.com/swedenconnect/signservice/tree/main/audit/actuator). |


<a name="protocol-configuration"></a>
#### Protocol Configuration

A [ProtocolHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/protocol/ProtocolHandler.java) instance is configured using the following configuration where one, and only one, setting should be supplied.

| Property | Description |
| :--- | :--- |
| `external.bean-name` | A bean name for an externally created handler bean. |
| `dss.*` | A protocol handler implementation according to the extensions of OASIS DSS 1.1 (https://docs.swedenconnect.se/technical-framework/). See [DssProtocolHandler](https://github.com/swedenconnect/signservice/tree/main/protocol/dss-ext11). |

<a name="authentication-configuration"></a>
#### Authentication Configuration

An [AuthenticationHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/authn/AuthenticationHandler.java) instance is configured using the following configuration where one, and only one, setting should be supplied.

| Property | Description |
| :--- | :--- |
| `external.bean-name` | A bean name for an externally created handler bean. |
| `saml.*` | Configuration for a SAML-based authentication handler. See [DefaultSamlAuthenticationHandler](https://github.com/swedenconnect/signservice/tree/main/authn/saml#default-saml-authentication-handler) and [SwedenConnectSamlAuthenticationHandler](https://github.com/swedenconnect/signservice/tree/main/authn/saml#sweden-connect-saml-authentication-handler). |
| `mock.*` | Configuration for a mocked authentication handler. May be useful during development and testing. See [MockedAuthenticationHandlerConfiguration](https://github.com/swedenconnect/signservice/blob/main/authn/base/src/main/java/se/swedenconnect/signservice/authn/mock/MockedAuthenticationHandlerConfiguration.java). |

<a name="signature-handler-configuration"></a>
#### Signature Handler Configuration

A [SignatureHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/signature/SignatureHandler.java) instance is configured using the following configuration where one, and only one, setting should be supplied.

| Property | Description |
| :--- | :--- |
| `external.bean-name` | A bean name for an externally created handler bean. |
| `default-handler.*` | Configuration for a default signature handler. See [DefaultSignatureHandler](https://github.com/swedenconnect/signservice/tree/main/signhandler). |

<a name="key-and-certificate-handler-configuration"></a>
#### Key and Certificate Handler Configuration

A [KeyAndCertificateHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/certificate/KeyAndCertificateHandler.java) instance is configured using the following configuration where one, and only one, setting should be supplied.

| Property | Description |
| :--- | :--- |
| `external.bean-name` | A bean name for an externally created handler bean. |
| `cmc.*` | Configuration for a key and certificate handler that uses the CMC API to communicate with a CA. See [CMCKeyAndCertificateHandler](https://github.com/swedenconnect/signservice/tree/main/keycert/cmc). |
| `built-in-ca.*` | Configuration for a key and certificate handler that uses a built in CA (i.e., a CA that is configured as part of the SignService application). See [SimpleKeyAndCertificateHandler](https://github.com/swedenconnect/signservice/tree/main/keycert/simple). |

### Other Configuration

<a name="credential-configuration"></a>
#### Credential Configuration

Credentials for different purposes are used in the SignService configuration. They are all configured in the
same way. One, and only one, of the following properties must be set to configure a `PkiCredential` object.

`bean-reference` - A string that contains a registered bean name referring to an already created `PkiCredential`
object. This setting is used when the application code creates the credential object outside of the SignService
configuration.

`props.*` - Configuration of the `PkiCredential` object using property values. See [3.3.2](https://github.com/swedenconnect/credentials-support#generic-pkicredentialfactorybean-for-springboot-users) for the [credentials-support](https://github.com/swedenconnect/credentials-support) repository.

`cred` - Assignment of an already instantiated `PkiCredential`. This setting is not possible to use when 
configuring the application using properties files, only when a programmatic setup is made.

<a name="configuration-example"></a>
## Configuration Example

As part of the SignService repository will supply a demo SignService application. It is configured using the
settings documented on this page. We include the demo application configuration (YAML-file) below with comments that point out the features of the configuration system.

The demo application is configured with two clients (engines).

```
signservice:
  domain: localhost
  base-url: https://${signservice.domain}:${server.port}
  default-sign-service-id: https://localhost.swedenconnect.se/signservice
  system-audit:
    actuator:
      name: "SignService System Audit Logger"
      principal: "SignService"
  default-credential:    
    props:
      name: SignService
      resource: classpath:signservice.jks
      alias: signservice
      type: JKS
      password: secret
      key-password: secret

  #
  # Configuration for common beans used by several engine configurations
  #  
  common-beans:
  
  	# Configuration for a common protocol handler bean
    protocol:
      bean-name: signservice.DssProtocolHandler
      dss:
        include-assertion: true
        include-request-message: false
        
	# Configuration for a common signature handler bean
    sign:
      bean-name: signservice.DefaultSignatureHandler
      default-handler:
        name: DefaultSignatureHandler
        tbs-processors:
        - type: xml
          strict-processing: false
          include-issuer-serial: true
        - type: pdf
        
    # Configuration for a common key and certificate handler bean  
    cert:
      bean-name: signservice.BuiltInCa
      built-in-ca:
        base-url: ${signservice.base-url}
        ca-credential:
          props:            
            resource: classpath:ca/test-ca.jks
            type: JKS
            password: secret
            alias: test-ca
            key-password: secret
        ca-signing-algorithm: http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256                
        key-provider:
          security-provider: BC  
        cert-validity: P365D
        crl-validity: P2D
        crl-dp-path: /sign/signca/signca.crl
        crl-file-location: ${SIGNSERVICE_HOME}/signca/signca.crl
        default-value-policy-checker:
          default-reply: false
          rules:
          - attribute-type: rdn
            ref: "2.5.4.6"
            allowed-values:
            - SE
            
    # Configuration for a shared SAML metadata provider
    saml:
      metadata-provider:
        bean-name: signservice.SamlMetadataProvider
        url: https://eid.svelegtest.se/metadata/mdx/role/idp.xml
        backup-file: ${SIGNSERVICE_HOME}/sandbox-metadata.xml
        validation-certificate: classpath:sandbox/sandbox-metadata.crt

  #
  # Both engines use SAML as the authentication handler, and even though each engine
  # is its own SAML SP, they share most of the configuration. So set up a shared
  # configuration for a SAML authentication handler.
  #                        
  default-handler-config:
    authn:
      saml:
        saml-type: sweden-connect
        sp-paths:
          base-url: ${signservice.base-url}
        #
        # References the common MetadataProvider bean. Will be loaded when the
        # handler is created.
        #
        metadata-provider-ref: signservice.SamlMetadataProvider
        signature-credential:
          props:
            name: SignService SAML Signing
            resource: classpath:sandbox/saml-sp.jks
            alias: sign
            type: JKS
            password: secret
            key-password: secret
        decryption-credential:
          props:            
            name: SignService SAML Decryption
            resource: classpath:sandbox/saml-sp.jks
            alias: encrypt
            type: JKS
            password: secret
            key-password: secret
        sign-authn-requests: true
        require-encrypted-assertions: true
        response-validation:
          strict-validation: false
          require-signed-assertions: true
          allowed-clock-skew: PT60S
        message-replay-checker-ref: signservice.MessageReplayChecker 
        metadata:
          entity-categories:
          - http://id.elegnamnden.se/st/1.0/sigservice
          - http://id.elegnamnden.se/ec/1.0/loa3-pnr
          - http://id.swedenconnect.se/ec/sc/uncertified-loa3-pnr
          - http://id.elegnamnden.se/ec/1.0/eidas-naturalperson
          - http://id.elegnamnden.se/st/1.0/public-sector-sp
          - http://id.swedenconnect.se/contract/sc/sweden-connect
          - http://id.swedenconnect.se/contract/sc/eid-choice-2017
          - http://id.swedenconnect.se/general-ec/1.0/secure-authenticator-binding
          - http://id.swedenconnect.se/general-ec/1.0/accepts-coordination-number
          authn-requests-signed: true
          want-assertions-signed: true
          requested-attributes:
          - name: urn:oid:1.2.752.29.4.13
            required: false
          - name: urn:oid:1.2.752.201.3.4
            required: false
          service-names:
          - "sv-SignService Demo"
          - "en-SignService Demo"
          ui-info:
            display-names:
            - "sv-Sweden Connect Demo SignService"
            - "en-Sweden Connect Demo SignService"
            descriptions:
            - "sv-Sweden Connect Underskriftstjänst för test och demonstration"
            - "en-Sweden Connect SignService for test and demonstration"
            logos:
            - path: /images/logo.svg
              height: 56
              width: 280
            - path: /images/logo-notext.svg
              height: 256
              width: 256
          organization:
            names:
            - "sv-Sweden Connect"
            - "en-Sweden Connect"
            display-names:
            - "sv-Sweden Connect"
            - "en-Sweden Connect"
            urls:
            - "en-https://www.swedenconnect.se"
          contact-persons:
            support:
              company: "Sweden Connect"
              email-address: operations@swedenconnect.se
            technical:
              company: "Sweden Connect"
              email-address: operations@swedenconnect.se
              
  #
  # OK, the application common settings are done. Let's configure our engines.
  #
  engines:
  
  #
  # Configuration for the "Test my Signature"-client running on localhost. 
  # See https://github.com/idsec-solutions/signservice-integration.
  #
  - name: "test-my-signature-localhost"
    processing-paths:
    - /sign/testmysignature/signreq
    client:
      client-id: http://sandbox.swedenconnect.se/testmyeid
      trusted-certificates:
      - classpath:clients/test-my-signature/client.crt
    protocol:
      # Uses the common ProtocolHandler bean
      external:        
        bean-name: signservice.DssProtocolHandler
    authn:
      saml:
        # By including a reference to the shared SAML configuration we don't have
        # to repeat ourselves. The settings are merged into our configuration object,
        # and we only have to supply what is specific for our client.
        default-config-ref: authn.saml
        entity-id: http://sandbox.swedenconnect.se/testmyeid/localsign
        sp-paths:
          metadata-publishing-path: /sign/testmysignature/saml/metadata
          assertion-consumer-path: /sign/testmysignature/saml/sso
        metadata:
          ui-info:
            display-names:
            - "en-Test your eID (localhost)"
            - "sv-Testa ditt eID (localhost)"
            descriptions:
            - "en-Application for testing your eID (localhost)"
            - "sv-Applikation för att testa ditt eID (localhost)"
    sign:
      external:
        bean-name: signservice.DefaultSignatureHandler
    cert:
      external:
        bean-name: signservice.BuiltInCa
    audit:
      file:
        name: "test-my-signature-audit-logger"
        file-name: ${SIGNSERVICE_HOME}/testmysignature/audit.log
        
  #
  # Configuration for the "Signature Service Test Application" (https://sig.sandbox.swedenconnect.se/testsp).
  # Log in using the user "signserviceuser" with the password "signserviceuser".
  #
  - name: "signservice-test-localhost"
    processing-paths:
    - /sign/testapp/signreq
    client:
      client-id: https://eid2cssp.3xasecurity.com/sign
      trusted-certificates:
      - classpath:clients/signservice-testapp/eid2cssp.3xasecurity.com.crt
    protocol:
      external:
        bean-name: signservice.DssProtocolHandler
    authn:
      saml:        
        default-config-ref: authn.saml
        entity-id: https://localhost.swedenconnect.se/eid2cssp
        sp-paths:
          metadata-publishing-path: /sign/testapp/saml/metadata
          assertion-consumer-path: /sign/testapp/saml/sso
        preferred-binding: POST
        metadata:
          ui-info:
            display-names:
            - "en-Sweden Connect Localhost Signature Service Test"
            - "sv-Sweden Connect test för underskriftstjänster (localhost)"
            descriptions:
            - "en-Sweden Connect test application for signature services running on localhost"
            - "sv-Sweden Connect testapplikation för underskriftstjänster (localhost)"
    sign:
      external:
        bean-name: signservice.DefaultSignatureHandler
    cert:
      external:
        bean-name: signservice.BuiltInCa
    audit:
      file:
        name: "signservice-test-localhost-audit"
        file-name: ${SIGNSERVICE_HOME}/signservice-testapp/audit.log

```

-----

Copyright &copy; 2022, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).

