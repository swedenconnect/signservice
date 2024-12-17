![Logo](../docs/images/sweden-connect.png)


# signservice/authn

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-authn-parent/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-authn-parent)

-----

The `authn` directory contains implementations for an [AuthenticationHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/authn/AuthenticationHandler.java). This handler is used to authenticate the user as part of the signature process.

- [base](base) - Common definitions for authentication handlers and a mocked implementation for authentication (for testing).

- [saml](saml) - Implementations using SAML as the authentication mechanism.

-----

Copyright &copy; 2022-2024, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
