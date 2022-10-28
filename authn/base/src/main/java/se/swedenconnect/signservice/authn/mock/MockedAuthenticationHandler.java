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
package se.swedenconnect.signservice.authn.mock;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.xml.DOMUtils;
import se.idsec.signservice.xml.JAXBUnmarshaller;
import se.swedenconnect.signservice.authn.AuthenticationErrorCode;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.authn.AuthenticationResult;
import se.swedenconnect.signservice.authn.AuthenticationResultChoice;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.authn.UserAuthenticationException;
import se.swedenconnect.signservice.authn.impl.DefaultIdentityAssertion;
import se.swedenconnect.signservice.authn.impl.SimpleAuthnContextIdentifier;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.AbstractSignServiceHandler;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;
import se.swedenconnect.signservice.protocol.msg.AuthnRequirements;
import se.swedenconnect.signservice.protocol.msg.SignMessage;

/**
 * A mocked authentication handler that may be used in testing scenarios.
 */
@Slf4j
public class MockedAuthenticationHandler extends AbstractSignServiceHandler implements AuthenticationHandler {

  /** The default authentication context URI to use if none has been specified. */
  public static final String DEFAULT_LOA = "http://id.elegnamnden.se/loa/1.0/loa3";

  /** The attribute name for the "Sign message digest" attribute (urn:oid:1.2.752.201.3.14). */
  public static final String ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST = "urn:oid:1.2.752.201.3.14";

  /**
   * Default constructor.
   */
  public MockedAuthenticationHandler() {
    log.warn("{} created - DO NOT USE IN PRODUCTION", this.getClass().getSimpleName());
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public AuthenticationResultChoice authenticate(@Nonnull final AuthnRequirements authnRequirements,
      @Nullable final SignMessage signMessage, @Nonnull final SignServiceContext context)
      throws UserAuthenticationException {

    log.warn("{}: Handler '{}' called to authenticate user - DO NOT USE IN PRODUCTION", context.getId(),
        this.getName());

    final DefaultIdentityAssertion assertion = new DefaultIdentityAssertion();
    assertion.setScheme("SAML");
    assertion.setIdentifier(UUID.randomUUID().toString());
    assertion.setIssuer(authnRequirements.getAuthnServiceID());
    assertion.setAuthnContext(authnRequirements.getAuthnContextIdentifiers().isEmpty()
        ? new SimpleAuthnContextIdentifier(DEFAULT_LOA)
        : authnRequirements.getAuthnContextIdentifiers().get(0));
    assertion.setIssuanceInstant(Instant.now());
    assertion.setAuthnInstant(Instant.now().minusMillis(1000L));

    final List<IdentityAttribute<?>> attributes = new ArrayList<>();
    authnRequirements.getRequestedSignerAttributes().stream().forEach(attributes::add);

    if (signMessage != null) {
      // Issue a signMessageDigest - it's only possible if the sign message isn't encrypted ...
      try {
        final se.swedenconnect.schemas.csig.dssext_1_1.SignMessage dssSignMessage =
            JAXBUnmarshaller.unmarshall(DOMUtils.bytesToDocument(signMessage.getEncoding()),
                se.swedenconnect.schemas.csig.dssext_1_1.SignMessage.class);
        if (dssSignMessage.isSetMessage()) {
          attributes.add(this.issueSignMessageDigest(dssSignMessage.getMessage()));
        }
      }
      catch (final Exception e) {
        log.info("{}: Invalid SignMessage supplied", context.getId(), e);
      }
    }
    assertion.setIdentityAttributes(attributes);
    assertion.setEncodedAssertion("dummy-assertion".getBytes());

    final AuthenticationResult result = new AuthenticationResult() {

      private static final long serialVersionUID = 5094209594471602113L;

      @Override
      public boolean signMessageDisplayed() {
        return assertion.getIdentityAttributes().stream()
            .filter(a -> ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST.equals(a.getIdentifier())).findFirst().isPresent();
      }

      @Override
      public IdentityAssertion getAssertion() {
        return assertion;
      }
    };

    return new AuthenticationResultChoice(result);
  }

  /**
   * Issues an attribute holding the signMessageDigest value.
   *
   * @param message the message to hash
   * @return an attribute
   * @throws UserAuthenticationException for internal processing errors
   */
  @Nonnull
  private IdentityAttribute<?> issueSignMessageDigest(@Nonnull final byte[] message)
      throws UserAuthenticationException {

    try {
      final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
      final String encodedMessageContent = Base64.getEncoder().encodeToString(message);
      final byte[] digestValue = messageDigest.digest(encodedMessageContent.getBytes(StandardCharsets.UTF_8));
      final String attributeValue =
          String.format("http://www.w3.org/2001/04/xmlenc#sha256;%s", Base64.getEncoder().encodeToString(digestValue));

      return new StringSamlIdentityAttribute(ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST, "signMessageDigest", attributeValue);
    }
    catch (final Exception e) {
      throw new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR,
          "Failed to create signMessageDigest", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public AuthenticationResultChoice resumeAuthentication(@Nonnull final HttpServletRequest httpRequest,
      @Nonnull final SignServiceContext context) throws UserAuthenticationException {

    throw new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR,
        "Resumed authentication is not supported");
  }

  /** {@inheritDoc} */
  @Override
  public boolean canProcess(@Nonnull final HttpServletRequest httpRequest, @Nullable final SignServiceContext context) {
    return false;
  }

}
