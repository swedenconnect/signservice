![Logo](../../docs/images/sweden-connect.png)


# signservice/authn/base

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-authn-base/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-authn-base)

-----

## About

The `signservice-authn-base` module is intended to hold base classes and interfaces to be used for authentication.
Currently no such code is added to the module (it may change in the future when more authentication handlers
are added).

However, the `signservice-authn-base` module contains the [MockedAuthenticationHandler](https://github.com/swedenconnect/signservice/blob/main/authn/base/src/main/java/se/swedenconnect/signservice/authn/mock/MockedAuthenticationHandler.java). It may be used during testing or development and mocks an authentication (i.e., just tells the SignService system
that the user has been authenticated without actually doing anything).

The [MockedAuthenticationHandlerConfiguration](https://github.com/swedenconnect/signservice/blob/main/authn/base/src/main/java/se/swedenconnect/signservice/authn/mock/MockedAuthenticationHandlerConfiguration.java) can be used to
configure this handler.

-----

Copyright &copy; 2022-2024, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
