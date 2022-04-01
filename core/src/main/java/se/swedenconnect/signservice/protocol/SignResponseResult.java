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
package se.swedenconnect.signservice.protocol;

import java.io.Serializable;

/**
 * Representation of a result object that is included in a {@link SignResponseMessage}.
 */
public interface SignResponseResult extends Serializable {

  // TODO: Define generic error codes to be used by all protocol implementations ...

  /**
   * Predicate that tells if this message represents a successful operation.
   *
   * @return true for success, and false otherwise
   */
  boolean isSuccess();

  /**
   * Gets the (major) error code.
   *
   * @return the error code
   */
  String getErrorCode();

  /**
   * Gets a minor error code.
   *
   * @return the minor error code, or null if none is available
   */
  String getMinorErrorCode();

  /**
   * Gets the message of the result object.
   *
   * @return the message
   */
  String getMessage();

}
