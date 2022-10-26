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
package se.swedenconnect.signservice.audit.callback;

import javax.annotation.Nonnull;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.signservice.audit.base.AbstractAuditLoggerConfiguration;

/**
 * Configuration class for configuring a {@link CallbackAuditLogger}.
 */
public class CallbackAuditLoggerConfiguration extends AbstractAuditLoggerConfiguration {

  /** The audit logger listener. Mutually exclusive with {@code listener-ref}. */
  @Getter
  @Setter
  private AuditLoggerListener listener;

  /** The bean name of the audit logger listener object to use. Mutually exclusive with {@code listener}. */
  @Getter
  @Setter
  private String listenerRef;

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected String getDefaultFactoryClass() {
    return CallbackAuditLoggerFactory.class.getName();
  }

}
