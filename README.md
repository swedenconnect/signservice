![Logo](docs/images/sweden-connect.png)


# Signature Service according to the Swedish eID Framework

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This repository comprises of source code for building a Signature Service according to the Swedish eID 
Framework specifications - https://docs.swedenconnect.se/technical-framework.

-----

## Documentation

Go to https://docs.swedenconnect.se/signservice for documentation of how to understand and use this repository.

## Modules

This repository comprises of the following modules:

* [core](core) - Core API:s and classes.

* [authn](authn) - Support for user authentication.

* [protocol](protocol) - Protocol support.

* [signhandler](signhandler) - Implementation of a Signature Handler, responsible of creating signatures.

* [keycert](keycert) - Modules for generating signature keys and certificates.

* [signhandler](signhandler) - Module for creating signatures.

* [audit](audit) - Audit logging support.

* [engine](engine) - Signature Service processing logic engine.

* [config](config) - Application configuration support.

* [spring-boot-starter](spring-boot-starter) - A Spring Boot Starter module that is useful when building a Signature Service using Spring Boot.

* [app](app) - A sample Signature Service application built using Spring Boot. 

* [bom](bom) - A Maven Bill-of-Materials POM that is useful when building SignService applications.

-----

Copyright &copy; 2022, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
