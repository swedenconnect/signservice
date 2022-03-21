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
package se.swedenconnect.signservice.api.engine.impl;

import java.security.SignatureException;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.signservice.api.engine.SignRequestMessageVerifier;
import se.swedenconnect.signservice.api.engine.SignServiceErrorException;
import se.swedenconnect.signservice.api.engine.UnrecoverableErrorCodes;
import se.swedenconnect.signservice.api.engine.UnrecoverableSignServiceException;
import se.swedenconnect.signservice.api.engine.config.EngineConfiguration;
import se.swedenconnect.signservice.api.engine.session.EngineContext;
import se.swedenconnect.signservice.api.protocol.ProtocolProcessingRequirements;
import se.swedenconnect.signservice.api.protocol.ProtocolProcessingRequirements.SignatureRequirement;
import se.swedenconnect.signservice.api.protocol.SignRequestMessage;

/**
 * Default implementation of the {@link SignRequestMessageVerifier} interface.
 */
@Slf4j
public class DefaultSignRequestMessageVerifier implements SignRequestMessageVerifier {

  // TODO: Define settings regarding verifier parameters

  /** {@inheritDoc} */
  @Override
  public void verifyMessage(final SignRequestMessage signRequestMessage, final EngineConfiguration configuration,
      final EngineContext context) throws UnrecoverableSignServiceException, SignServiceErrorException {

    // Check the requesting client against our client configuration ...
    //
    if (!configuration.getClientConfiguration().getClientId().equals(signRequestMessage.getClientId())) {
      log.info("{}: Received request from client '{}' - expected '{}' [id: '{}']",
          configuration.getName(), signRequestMessage.getClientId(),
          configuration.getClientConfiguration().getClientId(), context.getId());

      throw new UnrecoverableSignServiceException(
          UnrecoverableErrorCodes.UNKNOWN_CLIENT, "Unknown clientID - " + signRequestMessage.getClientId());
    }

    // Next, check the signature on the message ...
    //
    final ProtocolProcessingRequirements processingRequirements = signRequestMessage.getProcessingRequirements();
    if (!signRequestMessage.isSigned()) {
      if (processingRequirements.getRequestSignatureRequirement() == SignatureRequirement.REQUIRED) {
        log.debug("{}: Message is not signed - this is required [id: '{}', request-id: '{}']",
            configuration.getName(), context.getId(), signRequestMessage.getRequestId());

        throw new UnrecoverableSignServiceException(
            UnrecoverableErrorCodes.AUTHN_FAILED, "Request message is not signed");
      }
      else {
        log.debug("{}: Message is not signed [id: '{}', request-id: '{}']",
            configuration.getName(), context.getId(), signRequestMessage.getRequestId());
      }
    }
    else {
      try {
        signRequestMessage.verifySignature(configuration.getClientConfiguration().getTrustedCertificates());

          log.debug("{}: Signature on message was successfully verified. [id: '{}', request-id: '{}']",
              configuration.getName(), context.getId(), signRequestMessage.getRequestId());
      }
      catch (final SignatureException e) {
        log.info("{}: Signature validation of sign request message failed - {}. [id: '{}', request-id: '{}']",
            configuration.getName(), e.getMessage(), context.getId(), signRequestMessage.getRequestId(), e);

        throw new UnrecoverableSignServiceException(
            UnrecoverableErrorCodes.AUTHN_FAILED, "Request message signature validation failed: " + e.getMessage());
      }
    }

    // Check conditions of the message

    // Replay

    // Other aspects ...


  }

}
