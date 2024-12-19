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
package se.swedenconnect.signservice.audit;

/**
 * Runtime exception class that is thrown if audit logging fails. There are basically two types of failures:
 * <ul>
 * <li>The underlying logging system reports an error, or,</li>
 * <li>An audit event is incorrect, for example missing some of its mandatory data.</li>
 * </ul>
 */
public class AuditLoggerException extends RuntimeException {

  /** For serializing. */
  private static final long serialVersionUID = -4136899216063988045L;

  /**
   * Constructor setting the error message.
   *
   * @param message the error message
   */
  public AuditLoggerException(final String message) {
    super(message);
  }

  /**
   * Constructor setting the error message and the cause of the error.
   *
   * @param message the error message
   * @param cause the cause of the error
   */
  public AuditLoggerException(final String message, final Throwable cause) {
    super(message, cause);
  }

}
