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
package se.swedenconnect.signservice.session;

import javax.servlet.http.HttpServletRequest;

/**
 * The session handler is used by the SignService as an abstraction of handling sessions.
 */
public interface SessionHandler {

  /**
   * Gets the current session object, or if no session exists a new session object is created. Maps to
   * {@link #getSession(HttpServletRequest, boolean)} where {@code create} is {@code true}.
   *
   * @param httpRequest the HTTP servlet request
   * @return a session object
   */
  SignServiceSession getSession(final HttpServletRequest httpRequest);

  /**
   * Gets the current session object. If no session object exists a new session object is created if {@code created} is
   * set to {@code true}, otherwise {@code null} is returned.
   *
   * @param httpRequest The HTTP servlet request
   * @param create whether to create a new session object if no session object exists
   * @return a session object, or null
   */
  SignServiceSession getSession(final HttpServletRequest httpRequest, final boolean create);

  /**
   * Corresponds to {@link #getSession(HttpServletRequest)} but does not use a HTTP request as the base of maintaining
   * session.
   *
   * @param input the session maintainer
   * @return a session object
   */
  SignServiceSession getSession(final SessionMaintainer input);

  /**
   * Corresponds to {@link #getSession(HttpServletRequest, boolean))} but does not use a HTTP request as the base of
   * maintaining session.
   *
   * @param input the session maintainer
   * @param create whether to create a new session object if no session object exists
   * @return a session object, or null
   */
  SignServiceSession getSession(final SessionMaintainer input, final boolean create);

}
