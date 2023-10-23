/*
 * Copyright 2022-2023 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.signservice.config.audit;

import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.actuator.ActuatorAuditLoggerConfiguration;
import se.swedenconnect.signservice.audit.callback.CallbackAuditLoggerConfiguration;
import se.swedenconnect.signservice.audit.file.FileAuditLoggerConfiguration;
import se.swedenconnect.signservice.audit.logsystem.LogSystemAuditLoggerConfiguration;
import se.swedenconnect.signservice.config.HandlerConfigurationProperties;
import se.swedenconnect.signservice.core.config.BeanReferenceHandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Properties for audit logger configuration.
 */
public class AuditLoggerConfigurationProperties implements HandlerConfigurationProperties<AuditLogger> {

  /**
   * Configuration that points to an already configured audit logger bean.
   */
  private BeanReferenceHandlerConfiguration<AuditLogger> external;

  /**
   * Configuration for file audit logging.
   */
  @Getter
  @Setter
  private FileAuditLoggerConfiguration file;

  /**
   * Configuration for audit logging using an underlying log system.
   */
  @Getter
  @Setter
  private LogSystemAuditLoggerConfiguration logSystem;

  /**
   * Configuration for audit logging using callbacks to a listener.
   */
  @Getter
  @Setter
  private CallbackAuditLoggerConfiguration callback;

  /**
   * Configuration for using Spring Boot's actuator for audit logging.
   */
  @Getter
  @Setter
  private ActuatorAuditLoggerConfiguration actuator;

  /** {@inheritDoc} */
  @Override
  @Nullable
  public BeanReferenceHandlerConfiguration<AuditLogger> getExternal() {
    return this.external;
  }

  /** {@inheritDoc} */
  @Override
  public void setExternal(@Nullable final BeanReferenceHandlerConfiguration<AuditLogger> external) {
    this.external = external;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public HandlerConfiguration<AuditLogger> getHandlerConfiguration() throws IllegalArgumentException {
    final int noAssigned =
        (this.external != null ? 1 : 0) + (this.file != null ? 1 : 0) + (this.logSystem != null ? 1 : 0)
            + (this.callback != null ? 1 : 0)
            + (this.actuator != null && Optional.ofNullable(this.actuator.getActive()).orElse(true) ? 1 : 0);
    if (noAssigned > 1) {
      throw new IllegalArgumentException("Several audit configurations supplied, only one can be assigned");
    }
    else if (noAssigned == 0) {
      throw new IllegalArgumentException("Missing configuration");
    }
    return this.file != null ? this.file
        : this.logSystem != null ? this.logSystem
            : this.callback != null ? this.callback
                : this.actuator != null && Optional.ofNullable(this.actuator.getActive()).orElse(true) ? this.actuator
                    : this.external;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public HandlerConfiguration<AuditLogger> getHandlerConfiguration(@Nonnull final String name) {
    if ("file".equalsIgnoreCase(name)) {
      return this.file;
    }
    else if ("log-system".equalsIgnoreCase(name) || "logSystem".equalsIgnoreCase(name)
        || "LOG_SYSTEM".equalsIgnoreCase(name)) {
      return this.logSystem;
    }
    else if ("callback".equalsIgnoreCase(name)) {
      return this.callback;
    }
    else if ("actuator".equalsIgnoreCase(name)) {
      return this.actuator;
    }
    else if ("external".equalsIgnoreCase(name)) {
      return this.external;
    }
    else {
      return null;
    }
  }

}
