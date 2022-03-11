/*
 * MIT License
 *
 * Copyright 2022 Sweden Connect
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
