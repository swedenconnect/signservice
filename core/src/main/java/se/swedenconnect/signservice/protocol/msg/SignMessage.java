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
package se.swedenconnect.signservice.protocol.msg;

import java.io.Serializable;

/**
 * A representation of a sign message. The sign message is a protocol specific extension.
 */
public interface SignMessage extends Serializable {

  /**
   * Gets the encoding of the "sign message".
   *
   * @return the sign message encoding
   */
  byte[] getEncoding();

  /**
   * Tells whether the requester requires that the "sign message" is displayed for the user during the signature
   * operation.
   *
   * @return true if the sign message must be displayed, and false if it does not have to be displayed
   */
  boolean getMustShow();

}
