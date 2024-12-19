/*
 * Copyright 2022-2024 Sweden Connect
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
package se.swedenconnect.signservice.audit.callback;

import org.apache.commons.lang3.StringUtils;

import jakarta.annotation.Nonnull;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.base.AbstractAuditLogger;
import se.swedenconnect.signservice.audit.base.AbstractAuditLoggerFactory;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * A handler factory for creating {@link CallbackAuditLogger} instances.
 */
public class CallbackAuditLoggerFactory extends AbstractAuditLoggerFactory {

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected AbstractAuditLogger createAuditLogger(
      @Nonnull final HandlerConfiguration<AuditLogger> configuration, @Nonnull final BeanLoader beanLoader)
      throws IllegalArgumentException {

    if (configuration == null) {
      throw new IllegalArgumentException("Missing configuration for " + CallbackAuditLogger.class.getSimpleName());
    }

    if (!CallbackAuditLoggerConfiguration.class.isInstance(configuration)) {
      throw new IllegalArgumentException(
          "Unknown configuration object supplied - " + configuration.getClass().getSimpleName());
    }
    final CallbackAuditLoggerConfiguration conf = CallbackAuditLoggerConfiguration.class.cast(configuration);
    AuditLoggerListener listener = null;
    if (conf.getListener() != null) {
      listener = conf.getListener();
    }
    else if (StringUtils.isNotBlank(conf.getListenerRef())) {
      if (beanLoader == null) {
        throw new IllegalArgumentException("No bean loader provided - can not load listener-ref");
      }
      listener = beanLoader.load(conf.getListenerRef(), AuditLoggerListener.class);
    }
    if (listener == null) {
      throw new IllegalArgumentException("Missing audit logger listener");
    }
    return new CallbackAuditLogger(listener);
  }

}
