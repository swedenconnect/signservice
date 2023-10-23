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
package se.swedenconnect.signservice.audit.actuator;

import javax.annotation.Nonnull;

import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.callback.AuditLoggerListener;
import se.swedenconnect.signservice.audit.callback.CallbackAuditLogger;

/**
 * An {@link AuditLogger} Spring actuator implementation.
 */
public class ActuatorAuditLogger extends CallbackAuditLogger {

  /**
   * Constructor.
   *
   * @param listener the audit logger listener
   */
  public ActuatorAuditLogger(@Nonnull final AuditLoggerListener listener) {
    super(listener);
  }

}
