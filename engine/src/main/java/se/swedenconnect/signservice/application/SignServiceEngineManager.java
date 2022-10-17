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
package se.swedenconnect.signservice.application;

import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;
import se.swedenconnect.signservice.engine.SignServiceEngine;
import se.swedenconnect.signservice.engine.UnrecoverableErrorCodes;
import se.swedenconnect.signservice.engine.UnrecoverableSignServiceException;

/**
 * The SignService engine manager is responsible of routing every call to a matching engine and is seen as the main
 * SignService application bean.
 */
public interface SignServiceEngineManager {

  /**
   * Each HTTP message that is received by the SignService application on a given path is supplied to the
   * {@code processRequest} method.
   * <p>
   * Based on which URL the request was received a {@link SignServiceEngine} is selected, and its
   * {@link SignServiceEngine#processRequest(HttpServletRequest, HttpServletResponse)} method is called. If no matching
   * engine is found, an {@link UnrecoverableSignServiceException} exception with the code
   * {@link UnrecoverableErrorCodes#NOT_FOUND} will be thrown.
   * </p>
   * <p>
   * If the request is for a engine resource, the engine will write this resource to the {@code response} parameter and
   * return {@code null}. In all other cases the {@code processRequest} method will return a {@link HttpRequestMessage}
   * that signals a HTTP redirect or POST.
   * </p>
   *
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @return a HttpRequestMessage or null if a resource was written to the response parameter
   * @throws UnrecoverableSignServiceException for non-recoverable errors (should be displayed in an error view)
   */
  @Nullable
  HttpRequestMessage processRequest(
      @Nonnull final HttpServletRequest request, @Nonnull final HttpServletResponse response)
      throws UnrecoverableSignServiceException;

  /**
   * Gets a list of the SignService engines that this manager is configured to use.
   *
   * @return a list of engine instances
   */
  @Nonnull
  List<SignServiceEngine> getEngines();

  /**
   * Gets the system audit logger that this manager uses.
   *
   * @return the system audit logger
   */
  @Nonnull
  AuditLogger getSystemAuditLogger();

}
