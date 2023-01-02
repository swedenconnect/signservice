![Logo](../../docs/images/sweden-connect.png)


# signservice/protocol/dss-ext11

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-protocol-dssext11/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-protocol-dssext11)

-----

## About

SignService Protocol Handler for OASIS DSS 1.1 extensions - See https://docs.swedenconnect.se/technical-framework/.

### Configuration

The [DssProtocolHandler](https://github.com/swedenconnect/signservice/blob/main/protocol/dss-ext11/src/main/java/se/swedenconnect/signservice/protocol/dss/DssProtocolHandler.java) is configured using [DssProtocolHandlerConfiguration](https://github.com/swedenconnect/signservice/blob/main/protocol/dss-ext11/src/main/java/se/swedenconnect/signservice/protocol/dss/DssProtocolHandlerConfiguration.java). This class defines the following configuration settings:

| Property | Description | Default |
| :--- | :--- | :--- |
| `include-assertion` | Tells whether SAML assertions should be included in the response messages. | `true` |
| `include-request-message` | Tells whether to include the request message in the response messages created. For 1.1 version and below this will always be included, but in greater versions the field is optional (actually the specs dissuade from using it). | `false` |

-----

Copyright &copy; 2022-2023, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).