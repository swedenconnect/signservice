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
package se.swedenconnect.signservice.audit.logsystem;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.base.AbstractAuditLogger;
import se.swedenconnect.signservice.audit.base.AbstractAuditLoggerFactory;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * A handler factory for creating {@link LogSystemAuditLogger} instances.
 */
public class LogSystemAuditLoggerFactory extends AbstractAuditLoggerFactory {

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected AbstractAuditLogger createAuditLogger(
      @Nonnull final HandlerConfiguration<AuditLogger> configuration, @Nullable final BeanLoader beanLoader)
      throws IllegalArgumentException {

    if (configuration == null) {
      throw new IllegalArgumentException("Missing configuration for " + LogSystemAuditLogger.class.getSimpleName());
    }

    if (!LogSystemAuditLoggerConfiguration.class.isInstance(configuration)) {
      throw new IllegalArgumentException(
          "Unknown configuration object supplied - " + configuration.getClass().getSimpleName());
    }
    final LogSystemAuditLoggerConfiguration conf = LogSystemAuditLoggerConfiguration.class.cast(configuration);
    if (conf.getLoggerName() == null) {
      throw new IllegalArgumentException("The logger-name property must not be null");
    }
    return new LogSystemAuditLogger(conf.getLoggerName());
  }

}
