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
package se.swedenconnect.signservice.audit.file;

import java.io.IOException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.base.AbstractAuditLogger;
import se.swedenconnect.signservice.audit.base.AbstractAuditLoggerFactory;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * A handler factory for creating {@link FileAuditLogger} instances.
 */
public class FileAuditLoggerFactory extends AbstractAuditLoggerFactory {

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected AbstractAuditLogger createAuditLogger(
      @Nonnull final HandlerConfiguration<AuditLogger> configuration, @Nullable final BeanLoader beanLoader)
      throws IllegalArgumentException {

    if (configuration == null) {
      throw new IllegalArgumentException("Missing configuration for " + FileAuditLogger.class.getSimpleName());
    }
    if (!FileAuditLoggerConfiguration.class.isInstance(configuration)) {
      throw new IllegalArgumentException(
          "Unknown configuration object supplied - " + configuration.getClass().getSimpleName());
    }
    final FileAuditLoggerConfiguration conf = FileAuditLoggerConfiguration.class.cast(configuration);
    if (conf.getFileName() == null) {
      throw new IllegalArgumentException("The file-name property must not be null");
    }
    try {
      return new FileAuditLogger(conf.getFileName());
    }
    catch (final IOException e) {
      throw new IllegalArgumentException("Failed to create FileAuditLogger - " + e.getMessage(), e);
    }
  }

}
