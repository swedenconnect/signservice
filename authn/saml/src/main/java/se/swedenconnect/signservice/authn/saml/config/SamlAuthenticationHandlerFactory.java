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
package se.swedenconnect.signservice.authn.saml.config;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.commons.lang.StringUtils;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.UsageType;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.build.AssertionConsumerServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.KeyDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SPSSODescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.CompositeMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.request.AbstractAuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.request.DefaultAuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessor;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessorImpl;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.opensaml.sweid.saml2.request.SwedishEidAuthnRequestGenerator;
import se.swedenconnect.opensaml.sweid.saml2.signservice.SignMessageEncrypter;
import se.swedenconnect.opensaml.sweid.saml2.validation.SwedishEidResponseProcessorImpl;
import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectDecrypter;
import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectEncrypter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.authn.saml.DefaultSamlAuthenticationHandler;
import se.swedenconnect.signservice.authn.saml.MessageReplayCheckerWrapper;
import se.swedenconnect.signservice.authn.saml.SwedenConnectSamlAuthenticationHandler;
import se.swedenconnect.signservice.core.config.AbstractHandlerFactory;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Base class for factories creating SAML authentication handlers.
 */
@Slf4j
public class SamlAuthenticationHandlerFactory extends AbstractHandlerFactory<AuthenticationHandler> {

  /** {@inheritDoc} */
  @Override
  protected AuthenticationHandler createHandler(
      @Nonnull final HandlerConfiguration<AuthenticationHandler> configuration)
      throws IllegalArgumentException {

    if (configuration == null) {
      throw new IllegalArgumentException("Missing configuration for creating AuthenticationHandler instances");
    }
    if (!SamlAuthenticationHandlerConfiguration.class.isInstance(configuration)) {
      throw new IllegalArgumentException(
          "Unknown configuration object supplied - " + configuration.getClass().getSimpleName());
    }
    final SamlAuthenticationHandlerConfiguration conf =
        SamlAuthenticationHandlerConfiguration.class.cast(configuration);

    // Assert that required settings are there in the configuration object.
    //
    if (StringUtils.isBlank(conf.getEntityId())) {
      throw new IllegalArgumentException("Missing entityId from configuration object");
    }
    if (conf.getSpPaths() == null) {
      throw new IllegalArgumentException("No sp-paths assigned");
    }
    if (StringUtils.isBlank(conf.getSpPaths().getBaseUrl())) {
      throw new IllegalArgumentException("No sp-paths.base-url setting assigned");
    }

    if (StringUtils.isBlank(conf.getSamlType())) {
      conf.setSamlType(SamlAuthenticationHandlerConfiguration.SAML_TYPE_DEFAULT);
    }

    // Metadata provider
    //
    final MetadataProvider metadataProvider = this.createMetadataProvider(conf);

    // Metadata publishing
    //
    final EntityDescriptor entityDescriptor = this.createEntityDescriptor(conf);
    final PkiCredential mdSignCred = Optional.ofNullable(conf.getSignatureCredential())
        .orElseGet(() -> conf.getDefaultCredential());
    final EntityDescriptorContainer entityDescriptorContainer = new EntityDescriptorContainer(entityDescriptor,
        mdSignCred != null ? new OpenSamlCredential(mdSignCred) : null);

    // Response processor
    //
    final ResponseProcessor responseProcessor = this.createResponseProcessor(conf, metadataProvider);

    // AuthnRequest generator
    //
    final AuthnRequestGenerator authnRequestGenerator =
        this.createAuthnRequestGenerator(conf, metadataProvider, entityDescriptor);

    // Create the handler
    //
    return this.createHandler(conf, metadataProvider, entityDescriptorContainer, responseProcessor,
        authnRequestGenerator);
  }

  /**
   * Creates the SAML authentication handler.
   *
   * @param config the SAML configuration
   * @param metadataProvider the metadata provider
   * @param entityDescriptorContainer the metadata publisher
   * @param responseProcessor the response processor
   * @param authnRequestGenerator the AuthnRequest generator
   * @return a SAML authention handler
   */
  protected AuthenticationHandler createHandler(
      @Nonnull final SamlAuthenticationHandlerConfiguration config,
      @Nonnull final MetadataProvider metadataProvider,
      @Nonnull final EntityDescriptorContainer entityDescriptorContainer,
      @Nonnull final ResponseProcessor responseProcessor,
      @Nonnull final AuthnRequestGenerator authnRequestGenerator) {

    if (SamlAuthenticationHandlerConfiguration.SAML_TYPE_SWEDEN_CONNECT.equals(config.getSamlType())) {
      return new SwedenConnectSamlAuthenticationHandler(authnRequestGenerator, responseProcessor, metadataProvider,
          entityDescriptorContainer, config.getSpPaths());
    }
    else if (SamlAuthenticationHandlerConfiguration.SAML_TYPE_DEFAULT.equals(config.getSamlType())) {
      return new DefaultSamlAuthenticationHandler(authnRequestGenerator, responseProcessor, metadataProvider,
          entityDescriptorContainer, config.getSpPaths());
    }
    else {
      throw new IllegalArgumentException("Unknown saml-type - " + config.getSamlType());
    }
  }

  /**
   * Based on the configuration an {@link EntityDescriptor} is created.
   *
   * @param config the SAML configuration
   * @return an EntityDescriptor for the SP metadata
   */
  protected EntityDescriptor createEntityDescriptor(
      @Nonnull final SamlAuthenticationHandlerConfiguration config) {

    if (config.getMetadata() == null) {
      throw new IllegalArgumentException("Missing metadata configuration");
    }
    final MetadataConfiguration mdConfig = config.getMetadata();
    try {
      final EntityDescriptorBuilder builder = mdConfig.getTemplate() != null
          ? new EntityDescriptorBuilder(mdConfig.getTemplate())
          : new EntityDescriptorBuilder();

      // entityID
      builder.entityID(config.getEntityId());

      // Extensions
      final Extensions extensions = Optional.ofNullable(builder.object().getExtensions())
          .orElseGet(() -> ExtensionsBuilder.builder().build());

      // Entity categories
      if (mdConfig.getEntityCategories() != null && !mdConfig.getEntityCategories().isEmpty()) {
        extensions.getUnknownXMLObjects().add(
            EntityAttributesBuilder.builder()
                .entityCategoriesAttribute(mdConfig.getEntityCategories())
                .build());
      }

      if (builder.object().getExtensions() == null && !extensions.getUnknownXMLObjects().isEmpty()) {
        builder.object().setExtensions(extensions);
      }

      // Organization
      if (mdConfig.getOrganization() != null) {
        builder.organization(mdConfig.getOrganization().toElement());
      }

      // ContactPerson
      if (mdConfig.getContactPersons() != null && !mdConfig.getContactPersons().isEmpty()) {
        builder.contactPersons(mdConfig.getContactPersons().entrySet().stream()
            .map(e -> e.getValue().toElement(e.getKey()))
            .collect(Collectors.toList()));
      }

      // SPSSODescriptor
      //
      if (builder.object().getSPSSODescriptor(SAMLConstants.SAML20P_NS) == null) {
        builder.ssoDescriptor(SPSSODescriptorBuilder.builder().build());
      }
      final SPSSODescriptor desc = builder.object().getSPSSODescriptor(SAMLConstants.SAML20P_NS);

      // Want assertions signed?
      final Boolean wantAssertionsSigned = config.getResponseValidation() != null
          ? config.getResponseValidation().isRequireSignedAssertions()
          : null;
      desc.setWantAssertionsSigned(wantAssertionsSigned);

      // Is AuthnRequest messages signed?
      desc.setAuthnRequestsSigned(config.isSignAuthnRequests());

      // Extensions
      final Extensions descExtensions = Optional.ofNullable(desc.getExtensions())
          .orElseGet(() -> ExtensionsBuilder.builder().build());

      // UIInfo
      if (mdConfig.getUiInfo() != null) {
        descExtensions.getUnknownXMLObjects().add(mdConfig.getUiInfo().toElement(config.getSpPaths().getBaseUrl()));
      }

      // KeyDescriptors
      final List<KeyDescriptor> keyDescriptors = new ArrayList<>();
      if (config.getSignatureCredential() != null) {
        keyDescriptors.add(KeyDescriptorBuilder.builder()
            .use(UsageType.SIGNING)
            .keyName(config.getSignatureCredential().getName())
            .certificate(config.getSignatureCredential().getCertificate())
            .build());
      }
      if (config.getDecryptionCredential() != null) {
        keyDescriptors.add(KeyDescriptorBuilder.builder()
            .use(UsageType.ENCRYPTION)
            .keyName(config.getDecryptionCredential().getName())
            .certificate(config.getDecryptionCredential().getCertificate())
            .build());
        // TODO: Support for EncryptionMethod
      }
      if (config.getDefaultCredential() != null && keyDescriptors.size() < 2) {
        keyDescriptors.add(KeyDescriptorBuilder.builder()
            .use(UsageType.UNSPECIFIED)
            .keyName(config.getDefaultCredential().getName())
            .certificate(config.getDefaultCredential().getCertificate())
            .build());
      }
      if (!keyDescriptors.isEmpty()) {
        desc.getKeyDescriptors().clear();
        keyDescriptors.stream().forEach(k -> desc.getKeyDescriptors().add(k));
      }

      // NameIDFormat
      for (final String nameId : Arrays.asList(NameID.PERSISTENT, NameID.TRANSIENT)) {
        if (!desc.getNameIDFormats().stream().filter(n -> nameId.equals(n.getURI())).findFirst().isPresent()) {
          final NameIDFormat name = (NameIDFormat) XMLObjectSupport.buildXMLObject(NameIDFormat.DEFAULT_ELEMENT_NAME);
          name.setURI(nameId);
          desc.getNameIDFormats().add(name);
        }
      }

      // AttributeConsumingService
      final AttributeConsumingService attributeConsumingService = mdConfig.createAttributeConsumingServiceElement();
      if (attributeConsumingService != null) {
        desc.getAttributeConsumingServices().add(attributeConsumingService);
      }

      // AssertionConsumerService
      final List<AssertionConsumerService> acs = new ArrayList<>();
      int index = 0;
      if (StringUtils.isBlank(config.getSpPaths().getAssertionConsumerPath())) {
        throw new IllegalArgumentException("sp-paths.assertion-consumer-path must be set");
      }
      acs.add(AssertionConsumerServiceBuilder.builder()
          .binding(SAMLConstants.SAML2_POST_BINDING_URI)
          .location(String.format("%s%s",
              config.getSpPaths().getBaseUrl(), config.getSpPaths().getAssertionConsumerPath()))
          .index(index++)
          .isDefault(true)
          .build());
      if (StringUtils.isNotBlank(config.getSpPaths().getAdditionalAssertionConsumerPath())) {
        acs.add(AssertionConsumerServiceBuilder.builder()
            .binding(SAMLConstants.SAML2_POST_BINDING_URI)
            .location(String.format("%s%s",
                config.getSpPaths().getBaseUrl(), config.getSpPaths().getAdditionalAssertionConsumerPath()))
            .index(index++)
            .isDefault(false)
            .build());
      }
      desc.getAssertionConsumerServices().addAll(acs);

      if (desc.getExtensions() == null && !descExtensions.getUnknownXMLObjects().isEmpty()) {
        desc.setExtensions(descExtensions);
      }

      return builder.build();
    }
    catch (final MarshallingException | UnmarshallingException e) {
      throw new IllegalArgumentException("Failed to set up SP metadata", e);
    }
  }

  /**
   * Based on the SAML configuration and the metadata provider a {@link ResponseProcessor} is created.
   *
   * @param config the SAML configuration
   * @param metadataProvider the metadata provider
   * @return a ResponseProcessor
   */
  @Nonnull
  protected ResponseProcessor createResponseProcessor(
      @Nonnull final SamlAuthenticationHandlerConfiguration config,
      @Nonnull final MetadataProvider metadataProvider) {

    if (config.getMessageReplayChecker() == null) {
      throw new IllegalArgumentException("message-replay-checker must not be null");
    }

    SAMLObjectDecrypter objectDecrypter = null;
    if (config.getDecryptionCredential() != null || config.getDefaultCredential() != null) {
      final OpenSamlCredential cred = new OpenSamlCredential(config.getDecryptionCredential() != null
          ? config.getDecryptionCredential()
          : config.getDefaultCredential());
      objectDecrypter = new SAMLObjectDecrypter(cred);
    }
    if (config.isRequireEncryptedAssertions() && objectDecrypter == null) {
      throw new IllegalArgumentException("No decryption (or default) credential specified - "
          + "required since require-encrypted-assertions is true");
    }

    return this.createResponseProcessor(config, objectDecrypter,
        new MessageReplayCheckerWrapper(config.getMessageReplayChecker()), metadataProvider);
  }

  /**
   * Creates a {@link ResponseProcessor}.
   *
   * @param config the SAML configuration
   * @param decrypter object decrypter
   * @param messageReplayChecker the message replay checker
   * @param metadataProvider the metadata provider
   * @return a ResponseProcessor
   */
  @Nonnull
  protected ResponseProcessor createResponseProcessor(
      @Nonnull final SamlAuthenticationHandlerConfiguration config,
      @Nullable final SAMLObjectDecrypter decrypter,
      @Nonnull final MessageReplayChecker messageReplayChecker,
      @Nonnull final MetadataProvider metadataProvider) {

    ResponseProcessorImpl processor = null;
    if (SamlAuthenticationHandlerConfiguration.SAML_TYPE_SWEDEN_CONNECT.equalsIgnoreCase(config.getSamlType())) {
      processor = new SwedishEidResponseProcessorImpl();
    }
    else if (SamlAuthenticationHandlerConfiguration.SAML_TYPE_DEFAULT.equalsIgnoreCase(config.getSamlType())) {
      processor = new ResponseProcessorImpl();
    }
    else {
      throw new IllegalArgumentException("Unknown saml-type - " + config.getSamlType());
    }
    processor.setDecrypter(decrypter);
    processor.setMessageReplayChecker(messageReplayChecker);
    processor.setMetadataResolver(metadataProvider.getMetadataResolver());
    processor.setRequireEncryptedAssertions(config.isRequireEncryptedAssertions());
    processor.setResponseValidationSettings(config.getResponseValidation());
    try {
      processor.initialize();
    }
    catch (final ComponentInitializationException e) {
      throw new IllegalArgumentException("Failed to initialize SAML response processor - " + e.getMessage(), e);
    }
    return processor;
  }

  /**
   * Based on the configuration a {@link MetadataProvider} is created.
   *
   * @param config the configuration
   * @return a MetadataProvider
   */
  @Nonnull
  protected MetadataProvider createMetadataProvider(
      @Nonnull final SamlAuthenticationHandlerConfiguration config) {
    if (config.getMetadataProviders() == null || config.getMetadataProviders().isEmpty()) {
      throw new IllegalArgumentException("Missing metadata provider(s) from configuration object");
    }
    try {
      final List<MetadataProvider> providers = new ArrayList<>();
      for (final MetadataProviderConfiguration mc : config.getMetadataProviders()) {
        if (StringUtils.isNotBlank(mc.getUrl()) && StringUtils.isNotBlank(mc.getFile())) {
          throw new IllegalArgumentException("Illegal metadata provider configuration - Both url and file are set");
        }
        AbstractMetadataProvider provider = null;
        if (StringUtils.isNotBlank(mc.getUrl())) {
          provider = new HTTPMetadataProvider(mc.getUrl(), mc.getBackupFile(),
              HTTPMetadataProvider.createDefaultHttpClient(null /* trust all */, new DefaultHostnameVerifier()));
          if (mc.getValidationCertificate() == null) {
            log.warn("No validation certificate given for metadata provider ({}) - metadata can not be trusted",
                mc.getUrl());
          }
        }
        else if (StringUtils.isNotBlank(mc.getFile())) {
          provider = new FilesystemMetadataProvider(new File(mc.getFile()));
        }
        else {
          throw new IllegalArgumentException("Illegal metadata provider configuration - url or file must be set");
        }
        if (mc.getValidationCertificate() != null) {
          provider.setSignatureVerificationCertificate(mc.getValidationCertificate());
        }
        provider.setPerformSchemaValidation(false);
        providers.add(provider);
      }
      if (providers.size() > 1) {
        final CompositeMetadataProvider provider = new CompositeMetadataProvider("composite-provider", providers);
        provider.initialize();
        return provider;
      }
      else {
        providers.get(0).initialize();
        return providers.get(0);
      }
    }
    catch (final ResolverException | ComponentInitializationException e) {
      throw new IllegalArgumentException("Failed to initialize metadata provider - " + e.getMessage(), e);
    }
  }

  /**
   * Based on the SAML configuration, metadata provider and SP metadata an {@link AuthnRequestGenerator} is created.
   *
   * @param config the SAML configuration
   * @param metadataProvider the metadata provider
   * @param entityDescriptor the SP metadata
   * @return an AuthnRequestGenerator
   */
  @Nonnull
  protected AuthnRequestGenerator createAuthnRequestGenerator(
      @Nonnull final SamlAuthenticationHandlerConfiguration config,
      @Nonnull final MetadataProvider metadataProvider,
      @Nonnull final EntityDescriptor entityDescriptor) {

    final PkiCredential signCred = Optional.ofNullable(config.getSignatureCredential())
        .orElseGet(() -> config.getDefaultCredential());
    if (signCred == null && config.isSignAuthnRequests()) {
      throw new IllegalArgumentException("No signature (or default) credential specified");
    }
    final OpenSamlCredential cred = signCred != null ? new OpenSamlCredential(signCred) : null;

    AbstractAuthnRequestGenerator generator = null;
    if (SamlAuthenticationHandlerConfiguration.SAML_TYPE_SWEDEN_CONNECT.equalsIgnoreCase(config.getSamlType())) {
      generator =
          new SwedishEidAuthnRequestGenerator(entityDescriptor, cred, metadataProvider.getMetadataResolver());
      try {
        final SignMessageEncrypter encrypter =
            new SignMessageEncrypter(new SAMLObjectEncrypter(metadataProvider.getMetadataResolver()));
        ((SwedishEidAuthnRequestGenerator) generator).setSignMessageEncrypter(encrypter);
      }
      catch (final ComponentInitializationException e) {
        throw new IllegalArgumentException("Failed to initialize encrypter", e);
      }
    }
    else if (SamlAuthenticationHandlerConfiguration.SAML_TYPE_DEFAULT.equalsIgnoreCase(config.getSamlType())) {
      generator = new DefaultAuthnRequestGenerator(entityDescriptor, cred, metadataProvider.getMetadataResolver());
    }
    else {
      throw new IllegalArgumentException("Unknown saml-type - " + config.getSamlType());
    }
    try {
      generator.initialize();
    }
    catch (final ComponentInitializationException e) {
      throw new IllegalArgumentException("Failed to initialize AuthnRequest generator", e);
    }
    return generator;
  }

}
