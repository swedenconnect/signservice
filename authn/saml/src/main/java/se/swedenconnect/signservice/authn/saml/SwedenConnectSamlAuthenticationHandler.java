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
package se.swedenconnect.signservice.authn.saml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SSODescriptor;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingResult;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessor;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.MatchValue;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.PrincipalSelection;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.RequestedPrincipalSelection;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.MatchValueBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.PrincipalSelectionBuilder;
import se.swedenconnect.opensaml.sweid.saml2.request.SwedishEidAuthnRequestGeneratorContext;
import se.swedenconnect.signservice.authn.AuthenticationErrorCode;
import se.swedenconnect.signservice.authn.UserAuthenticationException;
import se.swedenconnect.signservice.authn.saml.config.SpUrlConfiguration;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;
import se.swedenconnect.signservice.protocol.msg.AuthnRequirements;
import se.swedenconnect.signservice.protocol.msg.SignMessage;
import se.swedenconnect.signservice.session.SignServiceContext;

/**
 * A SAML authentication handler that implements the SAML profiles stated in
 * <a href="https://docs.swedenconnect.se/technical-framework/">Sweden Connect eID Framework</a>.
 */
@Slf4j
public class SwedenConnectSamlAuthenticationHandler extends AbstractSamlAuthenticationHandler {

  /**
   * Constructor.
   *
   * @param authnRequestGenerator the generator for creating authentication requests
   * @param responseProcessor the SAML response processor
   * @param metadataProvider the SAML metadata provider
   * @param entityDescriptorContainer the container for this SP's metadata
   * @param urlConfiguration the URL configuration
   */
  public SwedenConnectSamlAuthenticationHandler(
      @Nonnull final AuthnRequestGenerator authnRequestGenerator,
      @Nonnull final ResponseProcessor responseProcessor,
      @Nonnull final MetadataProvider metadataProvider,
      @Nonnull final EntityDescriptorContainer entityDescriptorContainer,
      @Nonnull final SpUrlConfiguration urlConfiguration) {
    super(authnRequestGenerator, responseProcessor, metadataProvider, entityDescriptorContainer, urlConfiguration);
  }

  /**
   * Extends the base implementation with support for SignMessage and PrincipalSelection.
   */
  @Override
  protected AuthnRequestGeneratorContext createAuthnRequestContext(
      @Nonnull final AuthnRequirements authnRequirements, @Nullable final SignMessage signMessage,
      @Nonnull final SignServiceContext context, @Nonnull final EntityDescriptor idpMetadata)
      throws UserAuthenticationException {

    final AuthnRequestGeneratorContext defaultImpl =
        super.createAuthnRequestContext(authnRequirements, signMessage, context, idpMetadata);

    // If we received a SignMessage, unmarshall it to the OpenSAML representation ...
    //
    final se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessage openSamlSignMessage =
        this.unmarshallSignMessage(signMessage, context);

    // Handle the principal selection extension. Base it on what the IdP declares in its metadata.
    //
    final PrincipalSelection principalSelection = this.getPrincipalSelection(authnRequirements, context, idpMetadata);

    return new SwedishEidAuthnRequestGeneratorContext() {

      @Override
      @Nullable
      public PrincipalSelectionBuilderFunction getPrincipalSelectionBuilderFunction() {
        return () -> principalSelection != null ? principalSelection : null;
      }

      @Override
      @Nullable
      public RequestedAuthnContextBuilderFunction getRequestedAuthnContextBuilderFunction() {
        return defaultImpl.getRequestedAuthnContextBuilderFunction();
      }

      @Override
      @Nullable
      public SignMessageBuilderFunction getSignMessageBuilderFunction() {
        return (m, e) -> openSamlSignMessage != null ? openSamlSignMessage : null;
      }

    };
  }

  /**
   * Unmarshalls the encoded SignMessage from the generic representation to an OpenSAML
   * {@link se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessage} object.
   *
   * @param signMessage optional SignMessage
   * @param context the SignService context
   * @return the OpenSAML SignMessage, or null if no sign message is available
   * @throws UserAuthenticationException for unmarshalling errors
   */
  @Nullable
  private se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessage unmarshallSignMessage(
      @Nullable final SignMessage signMessage, @Nonnull final SignServiceContext context)
      throws UserAuthenticationException {

    if (signMessage == null) {
      return null;
    }
    try (final ByteArrayInputStream bis = new ByteArrayInputStream(signMessage.getEncoding())) {
      return se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessage.class.cast(
          XMLObjectSupport.unmarshallFromInputStream(XMLObjectProviderRegistrySupport.getParserPool(), bis));
    }
    catch (final IOException | XMLParserException | UnmarshallingException e) {
      final String msg = String.format("Failed to unmarshall SignMessage - %s", e.getMessage());
      log.info("{}: {}", context.getId(), msg);
      throw new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR, msg);
    }
  }

  /**
   * The {@code PrincipalSelection} is an extension defined in the specification <a href=
   * "https://docs.swedenconnect.se/technical-framework/latest/14_-_Principal_Selection_in_SAML_Authentication_Requests.html">Principal
   * Selection in SAML Authentication Requests</a>. We check if the IdP has declared support for any particular
   * attributes, and if the same are set in the {@code AuthnRequirements} we create a {@link PrincipalSelection} object
   * with these attributes.
   *
   * @param authnRequirements the authentication requirements
   * @param context the SignService context
   * @param idpMetadata the IdP metadata
   * @return a PrincipalSelection object or null
   */
  @Nullable
  private PrincipalSelection getPrincipalSelection(@Nonnull final AuthnRequirements authnRequirements,
      @Nonnull final SignServiceContext context, @Nonnull final EntityDescriptor idpMetadata) {

    final RequestedPrincipalSelection requestedPrincipalSelection =
        Optional.ofNullable(idpMetadata.getIDPSSODescriptor(SAMLConstants.SAML20P_NS))
            .map(SSODescriptor::getExtensions)
            .map(e -> EntityDescriptorUtils.getMetadataExtension(e, RequestedPrincipalSelection.class))
            .orElse(null);

    if (requestedPrincipalSelection == null) {
      log.debug("{}: IdP '{}' does not declare the RequestedPrincipalSelection extension "
          + "- will not include PrincipalSelection", context.getId(), idpMetadata.getEntityID());
      return null;
    }
    final List<MatchValue> matchValues = new ArrayList<>();
    for (final MatchValue mv : requestedPrincipalSelection.getMatchValues()) {
      final String value = authnRequirements.getRequestedSignerAttributes().stream()
          .filter(a -> a.getIdentifier().equals(mv.getName()))
          .filter(StringSamlIdentityAttribute.class::isInstance)
          .map(StringSamlIdentityAttribute.class::cast)
          .map(StringSamlIdentityAttribute::getValue)
          .findFirst()
          .orElse(null);
      if (value != null) {
        matchValues.add(MatchValueBuilder.builder()
            .name(mv.getName())
            .value(value)
            .build());
        log.debug("{}: Adding PrincipalSelection for attribute '{}' ...", context.getId(), mv.getName());
      }
    }
    if (matchValues.isEmpty()) {
      log.debug(
          "{}: No attributes in RequestedPrincipalSelection extension for IdP '{}' were "
              + "set in AuthnRequirements - will not include PrincipalSelection",
          context.getId(), idpMetadata.getEntityID());
      return null;
    }
    return PrincipalSelectionBuilder.builder()
        .matchValues(matchValues)
        .build();
  }

  /**
   * The SignMessage koncept should be supported by all IdP:s in the Sweden Connect federation.
   */
  @Override
  protected boolean isSignMessageSupported() {
    return true;
  }

  /**
   * Asserts that we received a signMessageDigest attribute if SignMessage was sent.
   */
  @Override
  protected void assertSignMessage(@Nullable final SignMessage signMessage,
      @Nonnull List<IdentityAttribute<?>> attributes, @Nonnull ResponseProcessingResult result,
      @Nonnull AuthnRequest authnRequest, @Nonnull SignServiceContext context) throws UserAuthenticationException {

    if (signMessage == null) {
      // No SignMessage was sent in AuthnRequest, nothing to assert ...
      return;
    }
    final StringSamlIdentityAttribute signMessageDigestAttribute = attributes.stream()
        .filter(a -> a.getIdentifier().equals(AttributeConstants.ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST))
        .filter(a -> Objects.nonNull(a.getValue()))
        .filter(StringSamlIdentityAttribute.class::isInstance)
        .map(StringSamlIdentityAttribute.class::cast)
        .findFirst()
        .orElse(null);
    if (signMessageDigestAttribute == null) {
      if (signMessage.getMustShow()) {
        final String msg = "The AuthnRequest stated that the SignMessage must be displayed by the IdP, but no "
            + "proof of this was included in the assertion (missing signMessageDigest attribute)";
        log.info("{}: {}", context.getId(), msg);
        throw new UserAuthenticationException(AuthenticationErrorCode.FAILED_AUTHN, msg);
      }
      else {
        log.info("{}: IdP did not include proof of SignMessage being displayed", context.getId());
      }
    }
  }

  /**
   * Returns {@code true} if the signMessageDigest attribute was received.
   */
  @Override
  protected boolean wasSignMessageDisplayed(@Nonnull final ResponseProcessingResult result,
      @Nonnull List<IdentityAttribute<?>> attributes, @Nonnull final AuthnRequest authnRequest,
      @Nonnull final SignServiceContext context) throws UserAuthenticationException {

    return attributes.stream()
        .filter(a -> a.getIdentifier().equals(AttributeConstants.ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST))
        .filter(StringSamlIdentityAttribute.class::isInstance)
        .map(StringSamlIdentityAttribute.class::cast)
        .findFirst()
        .isPresent();
  }

}
