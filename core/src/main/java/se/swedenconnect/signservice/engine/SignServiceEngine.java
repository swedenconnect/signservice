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
package se.swedenconnect.signservice.engine;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import se.swedenconnect.signservice.core.http.HttpRequestMessage;

/**
 * The main interface for SignService processing of signature requests.
 */
public interface SignServiceEngine {

  /**
   * The main entry point for a SignService Engine. The SignService application supplies the {@link HttpServletRequest}
   * and {@link HttpServletResponse} objects from the HTTP request that it is servicing and the engine processes it.
   * <p>
   * The internals, and the current state, of the engine will find out the type of message and process it accordingly.
   * </p>
   * <p>
   * Apart from processing requests, the engine may also serve resources. Examples of such resources are status pages
   * and authentication provider metadata. When a request being processed is a request for a resource the method will
   * not return a {@link HttpRequestMessage}, but instead {@code null} and write the resource to the supplied
   * {@link HttpServletResponse}. However, it will <b>not</b> commit the response. This is the responsibility of the
   * caller.
   * </p>
   *
   * @param httpRequest the HTTP request
   * @param httpResponse the HTTP response
   * @return a HttpRequestMessage that informs the calling application which HTTP message to send, or null if the
   *           request processed was a request to a resource
   * @throws UnrecoverableSignServiceException if a HTTP message can not be sent as a result of the processing. This can
   *           occur in cases when the engine can not successfully produce a response message to send
   */
  HttpRequestMessage processRequest(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse)
      throws UnrecoverableSignServiceException;

  /**
   * A predicate that given a request tells whether this engine instance can process the request.
   *
   * @param httpRequest the HTTP request
   * @return true if the engine can process the request and false otherwise
   */
  boolean canProcess(final HttpServletRequest httpRequest);

  /**
   * Initializes the engine bean.
   *
   * @throws Exception for init errors
   */
  @PostConstruct
  void init() throws Exception;

}
