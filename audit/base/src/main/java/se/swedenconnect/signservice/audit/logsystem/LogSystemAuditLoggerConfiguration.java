/*
 * Copyright 2022 Sweden Connect
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
package se.swedenconnect.signservice.audit.logsystem;

import java.util.Optional;

import javax.annotation.Nonnull;

import org.apache.commons.lang.StringUtils;

import se.swedenconnect.signservice.audit.base.AbstractAuditLoggerConfiguration;

/**
 * Handler configuration for creating {@link LogSystemAuditLogger} instances.
 */
public class LogSystemAuditLoggerConfiguration extends AbstractAuditLoggerConfiguration {

  /** The logger name to use for the log system audit logger. */
  private String loggerName;

  /**
   * Gets the logger name to use for the log system audit handler.
   *
   * @return the logger name
   */
  @Nonnull
  public String getLoggerName() {
    return this.loggerName;
  }

  /**
   * Assigns the logger name to use for the log system audit handler.
   *
   * @param loggerName the logger name
   */
  public void setLoggerName(@Nonnull final String loggerName) {
    this.loggerName = Optional.ofNullable(loggerName)
        .filter(StringUtils::isNotBlank)
        .orElseThrow(() -> new NullPointerException("loggerName must not be null or empty"));
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected String getDefaultFactoryClass() {
    return LogSystemAuditLoggerFactory.class.getName();
  }

}
