/*
 * Copyright 2022 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package se.swedenconnect.signservice.api.audit;

/**
 * Singleton that holds an {@link SignServiceAuditLogger} object in thread local storage (TLS). This
 * object will be initiated by the SignService Engine and may be used by SignService modules that
 * need access to the audit logger.
 */
public class SignServiceAuditLoggerSingleton {

  /** The audit logger. */
  private SignServiceAuditLogger auditLogger;

  /** The ThreadLocal ... */
  private final static ThreadLocal<SignServiceAuditLoggerSingleton> THREAD_LOCAL =
      new ThreadLocal<SignServiceAuditLoggerSingleton>() {
        @Override
        protected SignServiceAuditLoggerSingleton initialValue() {
          return new SignServiceAuditLoggerSingleton();
        }
      };

  /**
   * Is called to initialize the singleton with the audit logger it should carry.
   *
   * @param auditLogger the audit logger object
   */
  public static void init(final SignServiceAuditLogger auditLogger) {
    THREAD_LOCAL.get().auditLogger = auditLogger;
  }

  /**
   * Gets the audit logger object from the TLS.
   *
   * @return the audit logger object, or null if none has been set
   */
  public static SignServiceAuditLogger getAuditLogger() {
    return THREAD_LOCAL.get().auditLogger;
  }

  /**
   * Clears the object.
   */
  public static void clear() {
    THREAD_LOCAL.remove();
  }

  // Hidden constructor
  private SignServiceAuditLoggerSingleton() {}

}