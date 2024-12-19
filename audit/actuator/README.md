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

> Note: Using this audit logger it is not possible to separate audit logs from different clients. Which may be desirable in many cases.

### Configuration

The [ActuatorAuditLoggerConfiguration](https://github.com/swedenconnect/signservice/blob/main/audit/actuator/src/main/java/se/swedenconnect/signservice/audit/actuator/ActuatorAuditLoggerConfiguration.java) describes the configuration for an [ActuatorAuditLogger](https://github.com/swedenconnect/signservice/blob/main/audit/actuator/src/main/java/se/swedenconnect/signservice/audit/actuator/ActuatorAuditLogger.java) instance.

| Property | Description |
| :--- | :--- |
| `principal` | The default principal to assign to audit events. It should be equal to the clientID that the audit logger is servicing. If the audit logger is a system logger, the string "SignService" should be used. | 
| `active` | Whether actuator logging is enabled. The default is `true`. |

### Set up

The [ActuatorAuditLogger](https://github.com/swedenconnect/signservice/blob/main/audit/actuator/src/main/java/se/swedenconnect/signservice/audit/actuator/ActuatorAuditLogger.java) handler differs from other handlers since it 
relies on Spring and needs an `ApplicationEventPublisher` to function. Study the [signservice-spring-boot-starter](https://github.com/swedenconnect/signservice/tree/main/spring-boot-starter) to understand the steps required. 

-----

Copyright &copy; 2022-2024, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
