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
package se.swedenconnect.signservice.api.authn;

import javax.servlet.http.HttpServletRequest;
import se.swedenconnect.signservice.api.protocol.types.AuthnRequirements;
import se.swedenconnect.signservice.api.session.SignServiceContext;

/**
 * Defines the handler interface for user authentication.
 * <p>
 * Since the handler interface supports authentication schemes that can authenticate the user "in
 * one go" and schemes that require that the user is directed to a remote authentication service
 * (IdP) there are two methods defined:
 * </p>
 * <p>
 * <b>authenticate><b> - Initiates the authentication operation with the supplied authentication
 * requirements and the supplied session context. If the authentication can be performed without
 * directing the user to a remote authentication service the result is delivered directly in the
 * result object ({@link AuthenticationResult#getAssertion()}. If the user needs to be directed to a
 * remote authentication service the result object will contain the HTTP request object, see
 * {@link AuthenticationResult#getHttpRequestMessage()}. In these cases, the authentication process
 * is resumed by invoking {@code resumeAuthentication}.
 * </p>
 * <p>
 * <b>resumeAuthentication</b> - In the cases where a call to {@code authenticate} led to the user
 * being directed to a remote authentication service, this method resumes the authentication
 * process. Depending on the flow of the implemented authentication scheme the
 * {@code resumeAuthentication} may have to be invoked several times.
 * </p>
 */
public interface SignServiceAuthenticationHandler {

  /**
   * Gets the name of the handler.
   *
   * @return the handler name
   */
  String getName();

  /**
   * Initiates authentication of the user. Depending on the authentication scheme the return result
   * object may contain the authentication result (assertion) or a request to direct the user to a
   * remote service.
   *
   * @param authnRequirements the requested authentication requirements
   * @param context the SignService context
   * @return an AuthenticationResult object
   * @throws SignServiceAuthenticationException for authentication errors
   */
  AuthenticationResult authenticate(final AuthnRequirements authnRequirements,
      final SignServiceContext context) throws SignServiceAuthenticationException;

  /**
   * Resumes an authentication process.
   *
   * @param httpRequest the HTTP servlet request (containing authentication result from the remote
   *        authentication service)
   * @param context the SignService context
   * @return an AuthenticationResult object
   * @throws SignServiceAuthenticationException for authentication errors
   */
  AuthenticationResult resumeAuthentication(final HttpServletRequest httpRequest,
      final SignServiceContext context) throws SignServiceAuthenticationException;

}
