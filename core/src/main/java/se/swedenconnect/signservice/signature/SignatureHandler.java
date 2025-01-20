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
package se.swedenconnect.signservice.signature;

import java.security.SignatureException;

import jakarta.annotation.Nonnull;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.SignServiceHandler;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;

/**
 * A {@code SignatureHandler} instance is responsible of signing a supplied signature task using the provided
 * credential.
 */
public interface SignatureHandler extends SignServiceHandler {

  /**
   * Verifies that the requirements put in the supplied SignRequest is correct and the handler can process the request.
   * If not a {@link InvalidRequestException} is thrown.
   *
   * @param signRequest the request to check
   * @param context the SignService context
   * @throws InvalidRequestException if the requirements cannot be met
   */
  void checkRequirements(@Nonnull final SignRequestMessage signRequest, @Nonnull final SignServiceContext context)
      throws InvalidRequestException;

  /**
   * Signs the supplied signature task with the given signing credential.
   *
   * @param signatureTask the task to sign
   * @param signingCredential the signing credential
   * @param signRequest the SignRequest (that may contain input for the signature process)
   * @param context the SignService context
   * @return a completed signature task
   * @throws SignatureException for signing errors
   */
  @Nonnull
  CompletedSignatureTask sign(@Nonnull final RequestedSignatureTask signatureTask,
      @Nonnull final PkiCredential signingCredential, @Nonnull final SignRequestMessage signRequest,
      @Nonnull final SignServiceContext context) throws SignatureException;

}
