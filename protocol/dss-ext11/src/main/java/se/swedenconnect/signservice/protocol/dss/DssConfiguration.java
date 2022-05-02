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
package se.swedenconnect.signservice.protocol.dss;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;

/**
 * Configuration class for the DSS protocol handler.
 */
public class DssConfiguration implements Serializable {

  /** For serialization. */
  private static final long serialVersionUID = -5476399775119732046L;

  /**
   * Setting that tells whether SAML assertions should be included in the response messages. The default is to include
   * assertions.
   *
   * @param includeAssertion whether to include assertions in response messages
   * @return whether to include assertions in response messages
   */
  @Getter
  @Setter
  private boolean includeAssertion = true;

  /**
   * Setting that tells whether to include the request message in the response messages created. For 1.1 version and
   * below this will always be included, but in greater versions the field is optional (actually the specs dissuade from
   * using it). The default is not no include the request in responses.
   *
   * @param includeRequestMessage whether to include the request message in the response messages created
   * @return whether to include the request message in the response messages created
   */
  @Getter
  @Setter
  private boolean includeRequestMessage = false;
}
