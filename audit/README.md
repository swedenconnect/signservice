![Logo](../docs/images/sweden-connect.png)


# signservice/audit

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-audit-parent/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-audit-parent)

-----

The `audit` directory contains code for implementing the [AuditLogger](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/audit/AuditLogger.java) interface.


- [base](base) - Common code for all implementations. It also includes two implementations; a file based audit implementation and an implementation making use of an underlying log system (for example Logback or Log4j).

- [actuator](actuator) - A Spring Actuator implementation.

-----

Copyright &copy; 2022, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
