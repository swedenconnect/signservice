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
package se.swedenconnect.signservice.api.engine;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;

/**
 * The main interface for SignService processing of signature requests.
 */
public interface SignServiceEngine {

  /**
   * The main entry point for a SignService Engine. The SignService application supplies the
   * {@link HttpServletRequest} and {@link HttpServletResponse} objects from the HTTP request that
   * it is servicing and the engine processes it.
   * <p>
   * The internals, and the current state, of the engine will find out the type of message and
   * process it accordingly.
   * </p>
   *
   * @param httpRequest the HTTP request
   * @param httpResponse the HTTP response
   * @return a HttpRequestMessage that informs the calling application which HTTP message to send
   * @throws SignServiceUnrecoverableException if a HTTP message can not be sent as a result of the
   *         processing. This can occur in cases when the engine can not successfully produce a
   *         response message to send
   */
  HttpRequestMessage processRequest(final HttpServletRequest httpRequest,
      final HttpServletResponse httpResponse) throws SignServiceUnrecoverableException;

  /**
   * Gets the application unique name for this engine instance.
   *
   * @return the engine's name
   */
  String getEngineName();

  /**
   * A predicate that tells whether a request received by the SignService application on a certain
   * URL path can be processed by this engine instance.
   *
   * @param path the URL path (relative to the application root path)
   * @return true if this instance can process the request and false otherwise
   */
  boolean canProcess(final String path);

}
