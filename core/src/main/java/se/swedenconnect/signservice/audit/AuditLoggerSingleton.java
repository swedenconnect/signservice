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
package se.swedenconnect.signservice.audit;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

/**
 * Singleton that holds an {@link AuditLogger} object in thread local storage (TLS). This
 * object will be initiated by the SignService Engine and may be used by SignService modules that
 * need access to the audit logger.
 */
public class AuditLoggerSingleton {

  /** The audit logger. */
  private AuditLogger auditLogger;

  /** The ThreadLocal ... */
  private final static ThreadLocal<AuditLoggerSingleton> THREAD_LOCAL =
      new ThreadLocal<AuditLoggerSingleton>() {
        @Override
        protected AuditLoggerSingleton initialValue() {
          return new AuditLoggerSingleton();
        }
      };

  /**
   * Is called to initialize the singleton with the audit logger it should carry.
   *
   * @param auditLogger the audit logger object
   */
  public static void init(@Nonnull final AuditLogger auditLogger) {
    THREAD_LOCAL.get().auditLogger = auditLogger;
  }

  /**
   * Gets the audit logger object from the TLS.
   *
   * @return the audit logger object, or null if none has been set
   */
  @Nullable
  public static AuditLogger getAuditLogger() {
    return THREAD_LOCAL.get().auditLogger;
  }

  /**
   * Clears the object.
   */
  public static void clear() {
    THREAD_LOCAL.remove();
  }

  // Hidden constructor
  private AuditLoggerSingleton() {}

}
