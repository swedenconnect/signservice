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
package se.swedenconnect.signservice.engine;

import java.security.SignatureException;
import java.time.Duration;
import java.time.Instant;

import javax.annotation.Nonnull;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.signservice.engine.config.EngineConfiguration;
import se.swedenconnect.signservice.engine.session.EngineContext;
import se.swedenconnect.signservice.protocol.ProtocolProcessingRequirements;
import se.swedenconnect.signservice.protocol.ProtocolProcessingRequirements.SignatureRequirement;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.msg.MessageConditions;

/**
 * Default implementation of the {@link SignRequestMessageVerifier} interface.
 */
@Slf4j
public class DefaultSignRequestMessageVerifier implements SignRequestMessageVerifier {

  /** The clock skew that we accept during checks of time stamps. */
  private Duration allowedClockSkew = Duration.ofSeconds(30);

  /** The maximum amount of time that has passed since the request message was created. */
  private Duration maxMessageAge = Duration.ofMinutes(3);

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

    // Check that the message is intended for "me" ...
    //
    if (signRequestMessage.getSignServiceId() != null) {
      if (!signRequestMessage.getSignServiceId().equals(configuration.getSignServiceId())) {
        log.info("{} Invalid SignService ID is request ({}) - expected {} [id: '{}']",
            configuration.getName(), signRequestMessage.getSignServiceId(), configuration.getSignServiceId(),
            context.getId());

        throw new UnrecoverableSignServiceException(
            UnrecoverableErrorCodes.INVALID_MESSAGE_CONTENT,
            "Unexpected SignService ID in request - " + signRequestMessage.getSignServiceId());
      }
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
            UnrecoverableErrorCodes.AUTHN_FAILED, "Request message signature validation failed: " + e.getMessage(), e);
      }
    }

    // Check conditions of the message
    //
    final Instant issuedAt = signRequestMessage.getIssuedAt();
    if (issuedAt == null) {
      log.info("{}: Sign request message does not have an issued-at field [id: '{}', request-id: '{}']",
          configuration.getName(), context.getId(), signRequestMessage.getRequestId());
    }
    else {
      final Instant now = Instant.now();

      if (issuedAt.isAfter(now)) {
        // OK, this seems strange. Does the clock skew setting "save us"?
        if (issuedAt.toEpochMilli() - now.toEpochMilli() > this.allowedClockSkew.toMillis()) {
          final String msg = "The issued-at field of the sign request indicates that the message is not yet valid "
              + "- Possible clock skew error?";
          log.info("{}: {} [id: '{}', request-id: '{}']",
              configuration.getName(), msg, context.getId(), signRequestMessage.getRequestId());

          throw new SignServiceErrorException(new SignServiceError(SignServiceErrorCode.REQUEST_EXPIRED, null, msg));
        }
      }
      else if ((now.toEpochMilli() - issuedAt.toEpochMilli()) > (this.maxMessageAge.toMillis()
          + this.allowedClockSkew.toMillis())) {

        log.info("{}: The received sign request message has expired [id: '{}', request-id: '{}']",
            configuration.getName(), context.getId(), signRequestMessage.getRequestId());

        throw new SignServiceErrorException(new SignServiceError(SignServiceErrorCode.REQUEST_EXPIRED));
      }
    }

    // The client may also pass notBefore and notAfter conditions. Check those as well.
    // In these cases we don't include a clock skew. It is the client's responsibility
    // to set the range to cover for this.
    //
    final MessageConditions conditions = signRequestMessage.getConditions();
    if (conditions != null) {
      if (!conditions.isWithinRange(Instant.now())) {
        final String msg = "Verification of notBefore and notAfter condition failed";
        log.info("{}: {} [id: '{}', request-id: '{}']",
            configuration.getName(), msg, context.getId(), signRequestMessage.getRequestId());

        throw new SignServiceErrorException(new SignServiceError(SignServiceErrorCode.REQUEST_EXPIRED, msg));
      }
    }
  }

  /**
   * The clock skew that we accept during checks of time stamps. The default is 30 seconds.
   *
   * @param allowedClockSkew the allowed clock skew
   */
  public void setAllowedClockSkew(@Nonnull final Duration allowedClockSkew) {
    if (allowedClockSkew != null) {
      this.allowedClockSkew = allowedClockSkew;
    }
  }

  /**
   * The maximum amount of time that has passed since the request message was created.
   *
   * @param maxMessageAge the max message age
   */
  public void setMaxMessageAge(@Nonnull final Duration maxMessageAge) {
    if (maxMessageAge != null) {
      this.maxMessageAge = maxMessageAge;
    }
  }

}
