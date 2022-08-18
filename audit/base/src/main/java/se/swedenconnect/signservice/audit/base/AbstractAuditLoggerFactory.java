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
package se.swedenconnect.signservice.audit.base;

import java.lang.reflect.Constructor;
import java.util.Arrays;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.base.events.AuditEventFactory;
import se.swedenconnect.signservice.core.config.AbstractHandlerFactory;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * An abstract handler factory for creating {@link AuditLogger} instances.
 */
public abstract class AbstractAuditLoggerFactory extends AbstractHandlerFactory<AuditLogger> {

  /**
   * Based on the supplied configuration the method creates an {@link AuditLogger} instance. Note that the
   * implementation does not have to handle the setting of the handler name and the event factory. This is handled by
   * {@link AbstractAuditLoggerFactory#createHandler(HandlerConfiguration)}.
   *
   * @param configuration the configuration (may be null)
   * @return an audit logger instance
   * @throws IllegalArgumentException for configuration errors
   */
  @Nonnull
  protected abstract AbstractAuditLogger createAuditLogger(
      @Nullable final HandlerConfiguration<AuditLogger> configuration) throws IllegalArgumentException;

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected final AuditLogger createHandler(@Nullable final HandlerConfiguration<AuditLogger> configuration)
      throws IllegalArgumentException {

    final AbstractAuditLogger logger = this.createAuditLogger(configuration);

    if (configuration != null) {
      if (!AbstractAuditLoggerConfiguration.class.isInstance(configuration)) {
        throw new IllegalArgumentException(
            "Unknown configuration object supplied - " + configuration.getClass().getSimpleName());
      }
      final AbstractAuditLoggerConfiguration conf = AbstractAuditLoggerConfiguration.class.cast(configuration);
      logger.setName(conf.getName());
      if (conf.getPrincipal() != null) {
        logger.setDefaultPrincipal(conf.getPrincipal());
      }
      if (conf.getEventFactory() != null) {
        try {
          final Class<? extends AuditEventFactory> eventClass = conf.getEventFactory();

          final Constructor<?> ctor = Arrays.stream(eventClass.getDeclaredConstructors())
              .filter(c -> c.getParameterCount() == 0)
              .findFirst()
              .orElseThrow(
                  () -> new IllegalArgumentException("No no-arg constructor visible for " + eventClass));

          final AuditEventFactory factory = (AuditEventFactory) ctor.newInstance();
          logger.setEventFactory(factory);
        }
        catch (final Exception e) {
          throw new IllegalArgumentException(
              String.format("Failed to create event factory instance for %s - %s", conf.getEventFactory().getName(),
                  e.getMessage()),
              e);
        }
      }
    }

    return logger;
  }

}
