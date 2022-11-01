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
package se.swedenconnect.signservice.engine;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletResponse;

import se.swedenconnect.signservice.application.SignServiceProcessingResult;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;
import se.swedenconnect.signservice.core.http.HttpUserRequest;

/**
 * Interface for a SignService engine that is processing of signature requests.
 * <p>
 * A SignService engine is an instance serving one SignService client.
 * </p>
 */
public interface SignServiceEngine {

  /**
   * The main entry point for a SignService Engine. The SignService application supplies the
   * {@link HttpUserRequest} and {@link HttpServletResponse} objects from the HTTP request that
   * it is servicing and the engine processes it.
   * <p>
   * The internals, and the current state, of the engine will find out the type of message and
   * process it accordingly.
   * </p>
   * <p>
   * Apart from processing requests, the engine may also serve resources. Examples of such resources
   * are status pages and authentication provider metadata. When a request being processed is a
   * request for a resource the method will not return a {@link HttpRequestMessage}, but instead
   * {@code null} and write the resource to the supplied {@link HttpServletResponse}. However, it
   * will <b>not</b> commit the response. This is the responsibility of the caller.
   * </p>
   *
   * @param httpRequest the HTTP user request received by the SignService frontend/application
   * @param httpResponse the HTTP response
   * @return TODO
   * @throws UnrecoverableSignServiceException if a HTTP message can not be sent as a result of the
   *         processing. This can occur in cases when the engine can not successfully produce a
   *         response message to send
   */
  @Nonnull
  SignServiceProcessingResult processRequest(
      @Nonnull final HttpUserRequest httpRequest, @Nonnull final HttpServletResponse httpResponse,
      @Nullable final SignServiceContext signServiceContext) throws UnrecoverableSignServiceException;

  /**
   * A predicate that given a request tells whether this engine instance can process the request.
   *
   * @param request the HTTP user request received by the SignService frontend/application
   * @return true if the engine can process the request and false otherwise
   */
  boolean canProcess(@Nonnull final HttpUserRequest request);

  /**
   * Gets the name of the engine.
   *
   * @return the name
   */
  @Nonnull
  String getName();

  /**
   * Initializes the engine bean.
   *
   * @throws Exception for init errors
   */
  @PostConstruct
  void init() throws Exception;

}
