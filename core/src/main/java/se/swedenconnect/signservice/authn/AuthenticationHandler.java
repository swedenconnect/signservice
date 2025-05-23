/*
 * Copyright 2022-2025 Sweden Connect
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
package se.swedenconnect.signservice.authn;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.SignServiceHandler;
import se.swedenconnect.signservice.core.http.HttpUserRequest;
import se.swedenconnect.signservice.protocol.msg.AuthnRequirements;
import se.swedenconnect.signservice.protocol.msg.SignMessage;

/**
 * Defines the handler interface for user authentication.
 * <p>
 * Since the handler interface supports authentication schemes that can authenticate the user "in one go" and schemes
 * that require that the user is directed to a remote authentication service (IdP) there are two methods defined:
 * </p>
 * <p>
 * <b>authenticate</b> - Initiates the authentication operation with the supplied authentication requirements and the
 * supplied session context. If the authentication can be performed without directing the user to a remote
 * authentication service the result is delivered directly in the result object
 * {@link AuthenticationResultChoice#getAuthenticationResult()} If the user needs to be directed to a remote
 * authentication service the result object will contain the HTTP response action object, see
 * {@link AuthenticationResultChoice#getResponseAction()}. In these cases, the authentication process is resumed by
 * invoking {@code resumeAuthentication}.
 * </p>
 * <p>
 * <b>resumeAuthentication</b> - In the cases where a call to {@code authenticate} led to the user being directed to a
 * remote authentication service, this method resumes the authentication process. Depending on the flow of the
 * implemented authentication scheme the {@code resumeAuthentication} may have to be invoked several times.
 * </p>
 */
public interface AuthenticationHandler extends SignServiceHandler {

  /**
   * Initiates authentication of the user. Depending on the authentication scheme the return result object may contain
   * the authentication result (assertion) or a request to direct the user to a remote service.
   * <p>
   * It is the responsibility of {@code authenticate}, or {@code resumeAuthentication}, to assert that all requirements
   * from the supplied {@link AuthnRequirements} are fulfilled. This means that the authentication must assert the
   * supplied signer attributes ({@link AuthnRequirements#getRequestedSignerAttributes()}) and also check that the
   * authentication is performed under an accepted authentication context
   * ({@link AuthnRequirements#getAuthnContextIdentifiers()}).
   * </p>
   *
   * @param authnRequirements the requested authentication requirements
   * @param signMessage the sign message (optional)
   * @param context the SignService context
   * @return a choice object holding the authentication result or a HTTP request object (indicating that the user should
   *           be directed to an authentication service)
   * @throws UserAuthenticationException for authentication errors
   */
  @Nonnull
  AuthenticationResultChoice authenticate(@Nonnull final AuthnRequirements authnRequirements,
      @Nullable final SignMessage signMessage, @Nonnull final SignServiceContext context)
      throws UserAuthenticationException;

  /**
   * Resumes an authentication process.
   *
   * @param request the HTTP request received by the SignService frontend/application (containing authentication result
   *          from the remote authentication service)
   * @param context the SignService context
   * @return a choice object holding the authentication result or a HTTP response action object (indicating that the
   *           user should be directed to an authentication service)
   * @throws UserAuthenticationException for authentication errors
   */
  @Nonnull
  AuthenticationResultChoice resumeAuthentication(@Nonnull final HttpUserRequest request,
      @Nonnull final SignServiceContext context) throws UserAuthenticationException;

  /**
   * A predicate that given a request tells whether this handler can process the request. This method must be invoked
   * before {@link #resumeAuthentication(HttpUserRequest, SignServiceContext)} is called.
   *
   * @param request the HTTP request
   * @param context the SignService context (may be null depending on whether the invoking engine has set up a session
   *          or not)
   * @return true if the handler can process the request and false otherwise
   */
  boolean canProcess(@Nonnull final HttpUserRequest request, @Nullable final SignServiceContext context);
}
