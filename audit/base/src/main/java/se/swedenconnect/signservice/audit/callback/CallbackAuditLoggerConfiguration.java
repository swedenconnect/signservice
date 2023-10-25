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
package se.swedenconnect.signservice.audit.callback;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.audit.base.AbstractAuditLoggerConfiguration;

/**
 * Configuration class for configuring a {@link CallbackAuditLogger}.
 */
public class CallbackAuditLoggerConfiguration extends AbstractAuditLoggerConfiguration {

  /** The audit logger listener. Mutually exclusive with {@code listener-ref}. */
  private AuditLoggerListener listener;

  /** The bean name of the audit logger listener object to use. Mutually exclusive with {@code listener}. */
  private String listenerRef;

  /**
   * The audit logger listener. Mutually exclusive with {@code listener-ref}.
   *
   * @return the audit logger listener
   */
  @Nullable
  public AuditLoggerListener getListener() {
    return this.listener;
  }

  /**
   * The audit logger listener. Mutually exclusive with {@code listener-ref}.
   *
   * @param listener the audit logger listener
   */
  public void setListener(@Nonnull final AuditLoggerListener listener) {
    this.listener = listener;
  }

  /**
   * The bean name of the audit logger listener object to use. Mutually exclusive with {@code listener}.
   *
   * @return the listener reference
   */
  @Nullable
  public String getListenerRef() {
    return this.listenerRef;
  }

  /**
   * The bean name of the audit logger listener object to use. Mutually exclusive with {@code listener}.
   *
   * @param listenerRef the listener reference
   */
  public void setListenerRef(@Nonnull final String listenerRef) {
    this.listenerRef = listenerRef;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected String getDefaultFactoryClass() {
    return CallbackAuditLoggerFactory.class.getName();
  }

}
