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
package se.swedenconnect.signservice.api.protocol;

import java.util.List;
import javax.servlet.http.HttpServletRequest;
import se.swedenconnect.signservice.api.session.SignServiceContext;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;

/**
 * A handler interface for decoding and encoding Sign request and response messages.
 */
public interface SignServiceProtocolHandler {

  /**
   * Gets the name of this protocol handler instance.
   *
   * @return handler name
   */
  String getName();

  /**
   * Gets the protocol profiles that is supported by this handler.
   *
   * @return a list of protocol profiles
   */
  List<SignServiceProtocolProfile> getProtocolProfiles();

  /**
   * Given a message (the HTTP servlet request) and the context the handler decodes the message into
   * a {@link SignRequestMessage} instance.
   * <p>
   * No validation of the message is performed, other than ensuring that a decode operation is
   * possible. Use {@link SignRequestMessage#verifySignature(List)} and
   * {@link SignRequestMessage#verifyMessage()} to verify the integrity and correctness of the
   * message.
   * </p>
   *
   * @param httpRequest the HTTP servlet request from where the message can be obtained
   * @param context the SignService context
   * @return a SignRequestMessage
   * @throws SignServiceProtocolException for decoding errors
   */
  SignRequestMessage decodeRequest(final HttpServletRequest httpRequest,
      final SignServiceContext context) throws SignServiceProtocolException;

  // TODO: createSignResponseMessage(pars) - factory

  /**
   * Encodes a response message so that it can be returned to the SignService application. The
   * method will create a {@link HttpRequestMessage} representing the response message as a HTTP
   * request.
   *
   * @param responseMessage the response message to encode
   * @param context the SignService context
   * @return a HttpRequestMessage
   * @throws SignServiceProtocolException for encoding errors
   */
  HttpRequestMessage encodeResponse(final SignResponseMessage responseMessage,
      final SignServiceContext context) throws SignServiceProtocolException;

}
