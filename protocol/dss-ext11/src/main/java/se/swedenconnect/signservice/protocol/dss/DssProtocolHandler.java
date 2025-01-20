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
package se.swedenconnect.signservice.protocol.dss;

import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.xml.bind.JAXBException;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.xml.DOMUtils;
import se.swedenconnect.schemas.dss_1_0.SignRequest;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.AbstractSignServiceHandler;
import se.swedenconnect.signservice.core.http.DefaultHttpPostAction;
import se.swedenconnect.signservice.core.http.DefaultHttpResponseAction;
import se.swedenconnect.signservice.core.http.HttpPostAction;
import se.swedenconnect.signservice.core.http.HttpResponseAction;
import se.swedenconnect.signservice.core.http.HttpUserRequest;
import se.swedenconnect.signservice.engine.SignServiceError;
import se.swedenconnect.signservice.protocol.ProtocolException;
import se.swedenconnect.signservice.protocol.ProtocolHandler;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.SignResponseMessage;
import se.swedenconnect.signservice.protocol.SignResponseResult;
import se.swedenconnect.xml.jaxb.JAXBUnmarshaller;

/**
 * The {@link ProtocolHandler} implementation for sign request and response messages according to <a href=
 * "https://docs.swedenconnect.se/technical-framework/latest/09_-_DSS_Extension_for_Federated_Signing_Services.html">DSS
 * Extension for Federated Central Signing Services</a>.
 */
@Slf4j
public class DssProtocolHandler extends AbstractSignServiceHandler implements ProtocolHandler {

  /** The only binding that we support. */
  public static final String BINDING = "POST/XML/1.0";

  /** The configuration for response messages. */
  private DssSignResponseMessage.ResponseConfiguration responseConfiguration;

  /**
   * Default constructor.
   */
  public DssProtocolHandler() {
  }

  /**
   * Assigns the response message configuration
   *
   * @param responseConfiguration the response message configuration
   */
  public void setResponseConfiguration(
      @Nullable final DssSignResponseMessage.ResponseConfiguration responseConfiguration) {
    this.responseConfiguration = Optional.ofNullable(responseConfiguration)
        .orElseGet(() -> new DssSignResponseMessage.ResponseConfiguration());
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public SignRequestMessage decodeRequest(
      @Nonnull final HttpUserRequest httpRequest, @Nonnull final SignServiceContext context)
      throws ProtocolException {

    // We only handle POST ...
    //
    if (!"POST".equals(httpRequest.getMethod())) {
      log.info("Received {} request - The {} requires POST", httpRequest.getMethod(), this.getName());
      throw new ProtocolException("Invalid HTTP method - expected POST, but was " + httpRequest.getMethod());
    }

    // Read parameters and check parameters ...
    //
    final String binding = httpRequest.getParameter("Binding");
    if (StringUtils.isBlank(binding)) {
      log.info("No Binding attribute in request, assuming {}", BINDING);
    }
    else if (!BINDING.equals(binding)) {
      log.info("Unsupported Binding attribute ({}) - expected {}", binding, BINDING);
      throw new ProtocolException("Unsupported Binding - " + binding);
    }
    final String relayState = httpRequest.getParameter("RelayState");
    if (StringUtils.isBlank(relayState)) {
      final String msg = "No RelayState available in request message";
      log.info(msg);
      throw new ProtocolException(msg);
    }
    final String requestMessage = httpRequest.getParameter("EidSignRequest");
    if (StringUtils.isBlank(requestMessage)) {
      final String msg = "No SignRequest available in request message";
      log.info(msg);
      throw new ProtocolException(msg);
    }
    log.trace("Received SignRequest: {}", requestMessage);

    // Base64-decode the message and unmarshall it ...
    // The create the generic representation and make checks based on the specifications (what is required etc).
    //
    try {
      final Document node = DOMUtils.base64ToDocument(requestMessage);
      log.trace("Decoded received SignRequest: {}", DOMUtils.prettyPrint(node));

      final SignRequest dssSignRequest = JAXBUnmarshaller.unmarshall(node, SignRequest.class);

      final DssSignRequestMessage signRequestMessage = new DssSignRequestMessage(dssSignRequest, node);
      signRequestMessage.assertCorrectMessage();

      // Assert that the RelayState equals the request-id ...
      //
      if (!relayState.equals(signRequestMessage.getRequestId())) {
        final String msg = "RelayState does not match RequestID";
        log.info(msg);
        throw new ProtocolException(msg);
      }

      log.debug("Successfully received SignRequest message [client-id: '{}', request-id: '{}']",
          signRequestMessage.getClientId(), signRequestMessage.getRequestId());

      return signRequestMessage;
    }
    catch (final DOMException| IllegalArgumentException | JAXBException | DssProtocolException e) {
      final String msg = "Failed to decode/unmarshall SignRequest message - " + e.getMessage();
      log.info(msg, e);
      throw new ProtocolException(msg, e);
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public SignResponseMessage createSignResponseMessage(
      @Nonnull final SignServiceContext context, @Nonnull final SignRequestMessage signRequestMessage)
      throws ProtocolException {

    if (!DssSignRequestMessage.class.isInstance(signRequestMessage)) {
      final String msg = "Invalid call - Supplied request message must be of type DssSignRequestMessage";
      log.error("{}", msg);
      throw new IllegalArgumentException(msg);
    }
    final DssSignRequestMessage request = DssSignRequestMessage.class.cast(signRequestMessage);

    try {
      return new DssSignResponseMessage(this.responseConfiguration, request);
    }
    catch (final NullPointerException | IllegalArgumentException e) {
      final String msg = String.format("Cannot create DssSignResponseMessage - %s", e.getMessage());
      log.info("{}", msg, e);
      throw new ProtocolException(msg);
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public HttpResponseAction encodeResponse(
      @Nonnull final SignResponseMessage responseMessage, @Nonnull final SignServiceContext context)
      throws ProtocolException {

    if (responseMessage.getDestinationUrl() == null) {
      throw new ProtocolException("Can not encode SignResponse - destination URL is unknown");
    }
    final String encodedMessage = responseMessage.encode();

    final HttpPostAction action = DefaultHttpPostAction.builder()
        .url(responseMessage.getDestinationUrl())
        .parameter("EidSignResponse", encodedMessage)
        .parameter("RelayState", responseMessage.getRelayState())
        .parameter("Binding", BINDING)
        .build();

    return new DefaultHttpResponseAction(action);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public SignResponseResult translateError(@Nonnull final SignServiceError error) {
    return new DssSignResponseResult(error);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public SignResponseResult createSuccessResult() {
    final DssSignResponseResult result = new DssSignResponseResult();
    result.setMessage("Success");
    return result;
  }

}
