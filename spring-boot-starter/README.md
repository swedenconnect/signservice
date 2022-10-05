![Logo](../docs/images/sweden-connect.png)


# Spring Boot Starter for SignService applications

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-spring-boot-starter/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-spring-boot-starter)

-----

SignService Spring Boot Starter Module

## About

The SignService Spring Boot Starter is a support module for setting up a SignService application using Spring Boot.

## Configuration

The sections below describe the configuration settings supported, and all beans that are
created by the Spring Boot starter. Note that it is possible to override any bean by defining
a bean with the same name and type. In these cases, the starter will not create the bean.

### Application Beans and Configuration

#### Configuration

| Property | Description | Default |
| :--- | :--- | :--- |
| `signservice.domain` | The domain under which the SignService is running. | localhost |
| `signservice.base-url` | The "base URL" of the SignService, i.e., everything up until the context path. | `https://${signservice.domain}` |
| `signservice.engines[]` | A list of engine configurations. See "Engine Beans and Configuration" below. | An empty list |
| `signservice.default-credential.*` | It is possible to define a "default" credential that may be used in several engines. See section 3.3.2 in [credentials-support](https://github.com/swedenconnect/credentials-support#generic-pkicredentialfactorybean-for-springboot-users) for details on how to configure a credential. | - |

#### Beans

| Bean name | Type | Description |
| :--- | :--- | :--- |
| `signservice.Domain` | `String` | A bean holding a string for the domain under which the SignService is running. Created based on the `signservice.domain` property. |
| `signservice.BaseUrl` | `String` | A bean holding a string that contains the "base URL" of the SignService, i.e., everything up until the context path. Created based on the `signservice.base-url` property. |
| `signservice.ContextPath` | `String` | A bean holding the SignService context path (`server.servlet.context-path`). |
| `signservice.SessionHandler` | [SessionHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/session/SessionHandler.java) | If no `SessionHandler` bean has been defined, a default handler will be created. See [DefaultSessionHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/session/impl/DefaultSessionHandler.java). <br /> Note that this handler may very well work together with [Spring Session](https://spring.io/projects/spring-session). |
| `signservice.Engines` | List of [SignServiceEngine](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/engine/SignServiceEngine.java) | A list of the configured SignService engines. See configuration below. |
| `signservice.DefaultCredential` | [PkiCredential](https://github.com/swedenconnect/credentials-support/blob/main/src/main/java/se/swedenconnect/security/credential/PkiCredential.java) | A credential that may span over several engines. | 


> TODO

### Engine Beans and Configuration

#### Configuration

An engine is configured as part of the set of engines, see above. The below table describes
how one engine instance is configured.

| Property | Description |
| :--- | :--- |
| `name` | The name of the engine. |
| `sign-service-id` | The unique ID of the SignService. |
| `credential.*` | The SignService engine credential. See section 3.3.2 in [credentials-support](https://github.com/swedenconnect/credentials-support#generic-pkicredentialfactorybean-for-springboot-users) for details. If not configured, the `signservice.DefaultCredential` will be used.|
| `processing-path` | The engine processing path (relative to the application context path). |
| `client.*` | Client configuration. See below. |
| `protocol-handler-bean` | The bean name for the [ProtocolHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/protocol/ProtocolHandler.java) instance that this engine uses. If not assigned, the `signservice.DssProtocolHandler` bean will be assumed (see [Protocol Handler Beans and Configuration](#protocol-handler-beans-and-configuration) below). |

##### Client Configuration

| Property | Description |
| :--- | :--- |
| `client-id` | The unique client ID. |
| `certificates[]` | One or more resources pointing at certificates. These are the certificate(s) that the client uses to sign requests. |
| `response-urls[]` | Zero or more URL:s. These are pre-registered URL:s on which the client receives sign response messages. |


<a name="protocol-handler-beans-and-configuration"></a>
### Protocol Handler Beans and Configuration

A SignService may have several protocol handlers installed. Currently there is only one
implementation - for the DSS extensions protocol, see https://docs.swedenconnect.se/technical-framework.

#### Configuration

| Property | Description | Default |
| :--- | :--- | :--- |
| `signservice.protocol.dss11.`<br/>`include-assertion` | Tells whether SAML assertions should be included in the response messages. | `true` |
| `signservice.protocol.dss11.` <br />`include-request-message` | Tells whether to include the request message in the response messages created. For 1.1 version and below this will always be included, but in greater versions the field is optional (actually the specs dissuade from using it). | `false` |

#### Beans

| Bean name | Type | Description |
| :--- | :--- | :--- |
| `signservice.DssProtocolHandler` | [ProtocolHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/protocol/ProtocolHandler.java) | A protocol handler that implements the DSS extension specifications and profiles - see https://docs.swedenconnect.se/technical-framework. |

-----

Copyright &copy; 2022, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).