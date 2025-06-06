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
package se.swedenconnect.signservice.protocol;

import jakarta.annotation.Nonnull;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.SignServiceHandler;
import se.swedenconnect.signservice.core.http.HttpResponseAction;
import se.swedenconnect.signservice.core.http.HttpUserRequest;
import se.swedenconnect.signservice.engine.SignServiceError;

/**
 * A handler interface for decoding and encoding Sign request and response messages.
 */
public interface ProtocolHandler extends SignServiceHandler {

  /**
   * Given a message (the HTTP request received by the SignService frontend/application) and the context the handler
   * decodes the message into a {@link SignRequestMessage} instance.
   * <p>
   * No validation of the message is performed, other than ensuring that a decode operation is possible.
   * </p>
   *
   * @param httpRequest the HTTP request received by the SignService frontend/application
   * @param context the SignService context
   * @return a SignRequestMessage
   * @throws ProtocolException for decoding errors
   */
  @Nonnull
  SignRequestMessage decodeRequest(
      @Nonnull final HttpUserRequest httpRequest, @Nonnull final SignServiceContext context)
      throws ProtocolException;

  /**
   * A factory method that creates a {@link SignResponseMessage} given the context and the corresponding request
   * message.
   * <p>
   * Which parts of the {@link SignResponseMessage} that is populated is implementation dependent, but the
   * {@link ProtocolProcessingRequirements} of the created object will always be present, i.e.,
   * {@link SignRequestMessage#getProcessingRequirements()} will be non-null.
   * </p>
   *
   * @param context the SignService context
   * @param signRequestMessage the corresponding request message
   * @return a SignResponseMessage
   * @throws ProtocolException if a response message cannot be created
   */
  @Nonnull
  SignResponseMessage createSignResponseMessage(
      @Nonnull final SignServiceContext context, @Nonnull final SignRequestMessage signRequestMessage)
      throws ProtocolException;

  /**
   * Encodes a response message so that it can be returned to the SignService application. The method will create a
   * {@link HttpResponseAction} representing the response message as a HTTP request (redirect or post).
   *
   * @param responseMessage the response message to encode
   * @param context the SignService context
   * @return a HttpRequestMessage
   * @throws ProtocolException for encoding errors
   */
  @Nonnull
  HttpResponseAction encodeResponse(
      @Nonnull final SignResponseMessage responseMessage, @Nonnull final SignServiceContext context)
      throws ProtocolException;

  /**
   * Creates a {@link SignResponseResult} object indicating a successful response.
   *
   * @return a SignResponseResult object
   */
  @Nonnull
  SignResponseResult createSuccessResult();

  /**
   * Translates from the generic {@link SignServiceError} object to a protocol specific {@link SignResponseResult}
   * object.
   *
   * @param error the error to translate
   * @return a SignResponseResult
   */
  @Nonnull
  SignResponseResult translateError(@Nonnull final SignServiceError error);

}
