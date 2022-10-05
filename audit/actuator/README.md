![Logo](../../docs/images/sweden-connect.png)


# signservice/audit/actuator

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-audit-actuator/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-audit-actuator)

-----

## About

The `signservice-audit-actuator` provides an [AuditLogger](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/audit/AuditLogger.java) 
implementation that can audit log using Spring Boot's actuator feature.

## ActuatorAuditLogger

The [ActuatorAuditLogger](https://github.com/swedenconnect/signservice/blob/main/audit/actuator/src/main/java/se/swedenconnect/signservice/audit/actuator/ActuatorAuditLogger.java) is intended to be
used for SignService applications built using Spring Boot. It will publish audit logs that later will
be accessible from the `auditevents` actuator endpoint.

> Note: Using this audit logger it is not possible to separate audit logs from different clients.



> TODO: How to setup

-----

Copyright &copy; 2022, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
