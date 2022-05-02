![Logo](../docs/images/sweden-connect.png)


# SignService KeyAndCertificate Modules

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-engine/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-engine)

-----

The `keycert` directory contains code for implementing the [KeyAndCertificateHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/certificate/KeyAndCertificateHandler.java) API.

- [base](base) - Common code for all implementations.

- [simple](simple) - A simple implementation that generates keys in software and uses a built-in CA for issuing certificates.

- full - An implementation that supports generation of keys on a HSM and communication with an external CA.

> TODO: More

-----

Copyright &copy; 2022, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
