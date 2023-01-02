![Logo](../docs/images/sweden-connect.png)


# signservice/keycert

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-keycert-parent/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-keycert-parent)

-----

The `keycert` directory contains code for implementing the [KeyAndCertificateHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/certificate/KeyAndCertificateHandler.java) API.

- [base](base) - Common code for all implementations.

- [simple](simple) - An implementation that uses a built-in CA for issuing certificates.

- [cmc](cmc) - An implementation that communicates with an external CA using the CMC API.

-----

Copyright &copy; 2022-2023, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
