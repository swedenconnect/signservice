![Logo](../../docs/images/sweden-connect.png)


# signservice/audit/base

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-audit-base/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-audit-base)

-----

## About

The `signservice-audit-base` module contains implementations for a simple file based audit logger, an implementation that uses an underlying log system and a callback logger.

<a name="file-audit-logger"></a>
## FileAuditLogger

The [FileAuditLogger](https://github.com/swedenconnect/signservice/blob/main/audit/base/src/main/java/se/swedenconnect/signservice/audit/file/FileAuditLogger.java) is a simple implementation for those deployments that wish to audit log to files with no specific requirements regarding formatting of log entries. The implementation uses Java Util logging and imposes no specific requirements for any other log system.

The logger is "rolling" and a new log file is created per day.

### Configuration

The [FileAuditLoggerConfiguration](https://github.com/swedenconnect/signservice/blob/main/audit/base/src/main/java/se/swedenconnect/signservice/audit/file/FileAuditLoggerConfiguration.java) describes the configuration for a [FileAuditLogger](https://github.com/swedenconnect/signservice/blob/main/audit/base/src/main/java/se/swedenconnect/signservice/audit/file/FileAuditLogger.java) instance.

| Property | Description |
| :--- | :--- |
| `principal` | The default principal to assign to audit events. It should be equal to the clientID that the audit logger is servicing. If the audit logger is a system logger, the string "SignService" should be used. | 
| `file-name` | The audit log file name (including its full path). |

<a name="log-system-audit-logger"></a>
## LogSystemAuditLogger

The [LogSystemAuditLogger](https://github.com/swedenconnect/signservice/blob/main/audit/base/src/main/java/se/swedenconnect/signservice/audit/logsystem/LogSystemAuditLogger.java) is an implementation 
that that uses an underlying logsystem, via Slf4j, to produce audit log entries.

The underlying logsystem must be configured with a logger name corresponding to the logger name 
configured for this logger, see below.

The Logback configuration file below sets up a logger called `AUDIT_LOGGER`. This should be
configured for the [LogSystemAuditLogger](https://github.com/swedenconnect/signservice/blob/main/audit/base/src/main/java/se/swedenconnect/signservice/audit/logsystem/LogSystemAuditLogger.java).

Note that the log level should be `INFO`.

Using this strategy it is easy to have one SignService application that produces separate 
audit log files for different clients. Each client simply has its own logger and appender.

```
<configuration>

  <property name="AUDIT_LOG" value="logs/app.log"/>

  <appender name="AUDIT_APPENDER" class="ch.qos.logback.core.rolling.RollingFileAppender">
    <file>${AUDIT_LOG}</file>
    <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
      <fileNamePattern>logs/archived/app.%d{yyyy-MM-dd}.%i.log.gz</fileNamePattern>
      <maxFileSize>10MB</maxFileSize>
    </rollingPolicy>
    <encoder>
      <pattern>%d %p %c{1.} [%t] %m%n</pattern>
    </encoder>
  </appender>

  <logger name="AUDIT_LOGGER" level="INFO" additivity="false">
    <appender-ref ref="AUDIT_APPENDER"/>
  </logger>

</configuration>
```

### Configuration

The [LogSystemAuditLoggerConfiguration](https://github.com/swedenconnect/signservice/blob/main/audit/base/src/main/java/se/swedenconnect/signservice/audit/logsystem/LogSystemAuditLoggerConfiguration.java) describes the configuration for a [LogSystemAuditLogger](https://github.com/swedenconnect/signservice/blob/main/audit/base/src/main/java/se/swedenconnect/signservice/audit/logsystem/LogSystemAuditLogger.java) instance.

| Property | Description |
| :--- | :--- |
| `principal` | The default principal to assign to audit events. It should be equal to the clientID that the audit logger is servicing. If the audit logger is a system logger, the string "SignService" should be used. | 
| `logger-name` | The logger name to use for the log system audit logger. |

<a name="callback-audit-logger"></a>
## CallbackAuditLogger

The [CallbackAuditLogger](https://github.com/swedenconnect/signservice/blob/main/audit/base/src/main/java/se/swedenconnect/signservice/audit/callback/CallbackAuditLogger.java) is an implementation that offers an application
to define an [AuditLoggerListener](https://github.com/swedenconnect/signservice/blob/main/audit/base/src/main/java/se/swedenconnect/signservice/audit/callback/AuditLoggerListener.java) that will be handed all events logged by the
audit logger. This provides for great flexibility and the implementation of the listener can log in any way that the
application developer wants.

### Configuration

The [CallbackAuditLoggerConfiguration](https://github.com/swedenconnect/signservice/blob/main/audit/base/src/main/java/se/swedenconnect/signservice/audit/callback/CallbackAuditLoggerConfiguration.java) class describes the configuration for a [CallbackAuditLogger](https://github.com/swedenconnect/signservice/blob/main/audit/base/src/main/java/se/swedenconnect/signservice/audit/callback/CallbackAuditLogger.java) instance.

| Property | Description |
| :--- | :--- |
| `principal` | The default principal to assign to audit events. It should be equal to the clientID that the audit logger is servicing. If the audit logger is a system logger, the string "SignService" should be used. | 
| `listener` | An [AuditLoggerListener](https://github.com/swedenconnect/signservice/blob/main/audit/base/src/main/java/se/swedenconnect/signservice/audit/callback/AuditLoggerListener.java) instance. Mutually exclusive with `listener-ref`. |
| `listener-ref` | The name of a bean referring to an [AuditLoggerListener](https://github.com/swedenconnect/signservice/blob/main/audit/base/src/main/java/se/swedenconnect/signservice/audit/callback/AuditLoggerListener.java) instance. Mutually exclusive with `listener`. |

-----

Copyright &copy; 2022, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
