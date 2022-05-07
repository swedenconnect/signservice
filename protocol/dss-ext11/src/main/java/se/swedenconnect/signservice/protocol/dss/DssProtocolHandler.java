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
package se.swedenconnect.signservice.protocol.dss;

import java.util.Optional;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.JAXBException;

import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.xml.DOMUtils;
import se.idsec.signservice.xml.InternalXMLException;
import se.idsec.signservice.xml.JAXBUnmarshaller;
import se.swedenconnect.schemas.dss_1_0.SignRequest;
import se.swedenconnect.signservice.client.ClientConfiguration;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;
import se.swedenconnect.signservice.core.http.impl.DefaultHttpRequestMessage;
import se.swedenconnect.signservice.engine.SignServiceError;
import se.swedenconnect.signservice.protocol.ProtocolException;
import se.swedenconnect.signservice.protocol.ProtocolHandler;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.SignResponseMessage;
import se.swedenconnect.signservice.protocol.SignResponseResult;
import se.swedenconnect.signservice.session.SignServiceContext;

/**
 * The {@link ProtocolHandler} implementation for sign request and response messages according to <a href=
 * "https://docs.swedenconnect.se/technical-framework/latest/09_-_DSS_Extension_for_Federated_Signing_Services.html">DSS
 * Extension for Federated Central Signing Services</a>.
 */
@Slf4j
public class DssProtocolHandler implements ProtocolHandler {

  /** The default handler name. */
  public static final String DEFAULT_NAME = "DSS extensions Protocol Handler";

  /** The only binding that we support. */
  public static final String BINDING = "POST/XML/1.0";

  /** The context key for finding a client specific DSS configuration. */
  public static final String CLIENT_CONFIG_CONTEXT_KEY =
      String.format("%s.%s.%s", ClientConfiguration.class.getPackageName(),
          ClientConfiguration.class.getSimpleName(), DssConfiguration.class.getSimpleName());

  /** The handler name. */
  private String name;

  /** The protocol handler configuration. */
  private DssConfiguration configuration;

  /**
   * Default constructor.
   */
  public DssProtocolHandler() {
  }

  /**
   * Initializes the bean.
   */
  @PostConstruct
  public void init() {
    if (this.configuration == null) {
      log.info("No DSS protocol configuration supplied, using default configuration");
      this.configuration = new DssConfiguration();
    }
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return Optional.ofNullable(this.name).orElse(DEFAULT_NAME);
  }

  /**
   * Assigns the protocol handler name. If none is assigned, {@value #DEFAULT_NAME} will be used.
   *
   * @param name the name
   */
  public void setName(final String name) {
    this.name = name;
  }

  /** {@inheritDoc} */
  @Override
  public SignRequestMessage decodeRequest(final HttpServletRequest httpRequest, final SignServiceContext context)
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
    catch (final InternalXMLException | JAXBException | DssProtocolException e) {
      final String msg = "Failed to decode/unmarshall SignRequest message - " + e.getMessage();
      log.info(msg, e);
      throw new ProtocolException(msg, e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public SignResponseMessage createSignResponseMessage(final SignServiceContext context,
      final SignRequestMessage signRequestMessage) throws ProtocolException {

    if (!DssSignRequestMessage.class.isInstance(signRequestMessage)) {
      final String msg = "Invalid call - Supplied request message must be of type DssSignRequestMessage";
      log.error("{}", msg);
      throw new IllegalArgumentException(msg);
    }
    final DssSignRequestMessage request = DssSignRequestMessage.class.cast(signRequestMessage);

    // Normally the handler is configured to function for all clients, but a client configuration
    // may be setup so that the client has specific requirements on the protocol handler. In these
    // cases this is assigned in the context.
    //
    DssConfiguration config = context.get(CLIENT_CONFIG_CONTEXT_KEY, DssConfiguration.class);
    if (config == null) {
      config = this.getConfiguration();
    }

    try {
      return new DssSignResponseMessage(config, request);
    }
    catch (final NullPointerException | IllegalArgumentException e) {
      final String msg = String.format("Cannot create DssSignResponseMessage - %s", e.getMessage());
      log.info("{}", msg, e);
      throw new ProtocolException(msg);
    }
  }

  /** {@inheritDoc} */
  @Override
  public HttpRequestMessage encodeResponse(final SignResponseMessage responseMessage, final SignServiceContext context)
      throws ProtocolException {

    if (responseMessage.getDestinationUrl() == null) {
      throw new ProtocolException("Can not encode SignResponse - destination URL is unknown");
    }
    final String encodedMessage = responseMessage.encode();
    final DefaultHttpRequestMessage httpMsg = new DefaultHttpRequestMessage(
        responseMessage.getProcessingRequirements().getResponseSendMethod(), responseMessage.getDestinationUrl());
    httpMsg.addHttpParameter("EidSignResponse", encodedMessage);
    httpMsg.addHttpParameter("RelayState", responseMessage.getRelayState());
    httpMsg.addHttpParameter("Binding", BINDING);

    return httpMsg;
  }

  /** {@inheritDoc} */
  @Override
  public SignResponseResult translateError(final SignServiceError error) {
    return new DssSignResponseResult(error);
  }

  /**
   * Assigns the DSS protocol configuration.
   *
   * @param configuration the configuration
   */
  public void setConfiguration(final DssConfiguration configuration) {
    this.configuration = configuration;
  }

  /**
   * Gets the configuration to use.
   *
   * @return the configuration
   */
  private DssConfiguration getConfiguration() {
    if (this.configuration == null) {
      log.info("No DSS protocol configuration supplied, using default configuration");
      this.configuration = new DssConfiguration();
    }
    return this.configuration;
  }

}
