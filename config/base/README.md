![Logo](../../docs/images/sweden-connect.png)


# signservice/config/base

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-config/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-config)

-----

## About

The `signservice-config` module contains data classes for an easy<sup>*</sup> configuration of a SignService application
and factory support for creating a [SignServiceEngineManager](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/engine/SignServiceEngineManager.java).

The [SignServiceEngineManager](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/engine/SignServiceEngineManager.java) is basically the SignService application and 
contains all logic. So, what is needed by the application developer is basically a controller that invokes
the manager. See [Setting up a Signature Service Application](https://docs.swedenconnect.se/signservice/application.html).


> \[\*\]: No, it's not easy, but compared to setting up every required object by hand it is a walk in the park.

## The SignService Factory

The 

## SignService Configuration Properties

### Engine Configuration


-----

Copyright &copy; 2022, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
