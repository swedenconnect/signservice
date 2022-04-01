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

import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.JAXBException;

import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.xml.DOMUtils;
import se.idsec.signservice.xml.InternalXMLException;
import se.idsec.signservice.xml.JAXBUnmarshaller;
import se.swedenconnect.schemas.dss_1_0.SignRequest;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;
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
  public static final String EXPECTED_BINDING = "POST/XML/1.0";

  /** The handler name. */
  private String name;

  public DssProtocolHandler() {
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
      log.info("No Binding attribute in request, assuming {}", EXPECTED_BINDING);
    }
    else if (!EXPECTED_BINDING.equals(binding)) {
      log.info("Unsupported Binding attribute ({}) - expected {}", binding, EXPECTED_BINDING);
      throw new ProtocolException("Unsupported Binding - " + binding);
    }
    final String relayState = httpRequest.getParameter("RelayState");

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

      final DssSignRequestMessage signRequestMessage = new DssSignRequestMessage(dssSignRequest, node, relayState);
      signRequestMessage.assertCorrectMessage();

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

  @Override
  public SignResponseMessage createSignResponseMessage(SignServiceContext context,
      SignRequestMessage signRequestMessage) {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public HttpRequestMessage encodeResponse(SignResponseMessage responseMessage, SignServiceContext context)
      throws ProtocolException {
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public SignResponseResult translateError(final SignServiceError error) {
    return null;
  }

}
