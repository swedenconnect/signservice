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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.commons.lang.StringUtils;
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

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import se.swedenconnect.opensaml.common.builder.SAMLObjectBuilderRuntimeException;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.build.AssertionConsumerServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.KeyDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SPSSODescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.request.AbstractAuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.request.DefaultAuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessor;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessorImpl;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.opensaml.saml2.response.validation.ResponseValidationSettings;
import se.swedenconnect.opensaml.sweid.saml2.request.SwedishEidAuthnRequestGenerator;
import se.swedenconnect.opensaml.sweid.saml2.signservice.SignMessageEncrypter;
import se.swedenconnect.opensaml.sweid.saml2.validation.SwedishEidResponseProcessorImpl;
import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectDecrypter;
import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectEncrypter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.authn.saml.AbstractSamlAuthenticationHandler;
import se.swedenconnect.signservice.authn.saml.DefaultSamlAuthenticationHandler;
import se.swedenconnect.signservice.authn.saml.MessageReplayCheckerWrapper;
import se.swedenconnect.signservice.authn.saml.SwedenConnectSamlAuthenticationHandler;
import se.swedenconnect.signservice.core.config.AbstractHandlerFactory;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Base class for factories creating SAML authentication handlers.
 */
public class SamlAuthenticationHandlerFactory extends AbstractHandlerFactory<AuthenticationHandler> {

  /** {@inheritDoc} */
  @Override
  protected AuthenticationHandler createHandler(
      @Nonnull final HandlerConfiguration<AuthenticationHandler> configuration, @Nullable final BeanLoader beanLoader)
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
    this.assertSamlType(conf.getSamlType());
    
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
    if (conf.getMetadataProvider() != null && conf.getMetadataProviderRef() != null) {
      throw new IllegalArgumentException(
          "Illegal configuration - metadata-provider and metadata-provider-ref can not both be assigned");
    }
    MetadataProvider metadataProvider = null;
    if (conf.getMetadataProvider() != null) {
      metadataProvider = conf.getMetadataProvider().create();
    }
    else if (conf.getMetadataProviderRef() != null) {
      if (beanLoader == null) {
        throw new IllegalArgumentException(
            "Missing bean loader - cannot load bean referenced by metadata-provider-ref");
      }
      metadataProvider = beanLoader.load(conf.getMetadataProviderRef(), MetadataProvider.class);
    }
    else {
      throw new IllegalArgumentException("Missing metadata provider(s) from configuration object");
    }

    // Metadata publishing
    //
    final EntityDescriptor entityDescriptor = this.createEntityDescriptor(conf, beanLoader);
    final PkiCredential mdSignCred = Optional.ofNullable(conf.getSignatureCredential())
        .map(c -> c.resolvePkiCredential(beanLoader))
        .orElseGet(() -> {
          return Optional.ofNullable(conf.getDefaultCredential())
              .map(c -> c.resolvePkiCredential(beanLoader))
              .orElse(null);
        });
    final EntityDescriptorContainer entityDescriptorContainer = new EntityDescriptorContainer(entityDescriptor,
        mdSignCred != null ? new OpenSamlCredential(mdSignCred) : null);

    // Response processor
    //
    final ResponseProcessor responseProcessor = this.createResponseProcessor(conf, beanLoader, metadataProvider);

    // AuthnRequest generator
    //
    final AuthnRequestGenerator authnRequestGenerator =
        this.createAuthnRequestGenerator(conf, beanLoader, metadataProvider, entityDescriptor);

    // Request binding
    //
    final String requestBinding = conf.getPreferredBinding() != null
        ? "post".equalsIgnoreCase(conf.getPreferredBinding())
            ? SAMLConstants.SAML2_POST_BINDING_URI
            : SAMLConstants.SAML2_REDIRECT_BINDING_URI
        : SAMLConstants.SAML2_REDIRECT_BINDING_URI;

    // Create the handler
    //
    return this.createHandler(conf, metadataProvider, entityDescriptorContainer, responseProcessor,
        authnRequestGenerator, requestBinding);
  }

  /**
   * Asserts that a valid SAML type has been provided.
   * 
   * @param type the SAML type (if null, the default is assumed)
   * @throws IllegalArgumentException for invalid types
   */
  protected void assertSamlType(@Nullable final String type) throws IllegalArgumentException {
    if (type == null) {
      return;
    }
    if (!SamlAuthenticationHandlerConfiguration.SAML_TYPE_SWEDEN_CONNECT.equals(type)
        && !SamlAuthenticationHandlerConfiguration.SAML_TYPE_DEFAULT.equals(type)) {
      throw new IllegalArgumentException("Unknown saml-type - " + type);
    }
  }

  /**
   * Creates the SAML authentication handler.
   *
   * @param config the SAML configuration
   * @param metadataProvider the metadata provider
   * @param entityDescriptorContainer the metadata publisher
   * @param responseProcessor the response processor
   * @param authnRequestGenerator the AuthnRequest generator
   * @param preferredRequestBinding the preferred request binding URI
   * @return a SAML authention handler
   */
  protected AuthenticationHandler createHandler(
      @Nonnull final SamlAuthenticationHandlerConfiguration config,
      @Nonnull final MetadataProvider metadataProvider,
      @Nonnull final EntityDescriptorContainer entityDescriptorContainer,
      @Nonnull final ResponseProcessor responseProcessor,
      @Nonnull final AuthnRequestGenerator authnRequestGenerator,
      @Nonnull final String preferredRequestBinding) {

    AbstractSamlAuthenticationHandler handler = null;
    if (SamlAuthenticationHandlerConfiguration.SAML_TYPE_SWEDEN_CONNECT.equals(config.getSamlType())) {
      handler = new SwedenConnectSamlAuthenticationHandler(authnRequestGenerator, responseProcessor, metadataProvider,
          entityDescriptorContainer, config.getSpPaths());
      
      if (config.getSadRequest() != null) {
        ((SwedenConnectSamlAuthenticationHandler) handler).setSadRequestRequirement(config.getSadRequest());
      }
      ((SwedenConnectSamlAuthenticationHandler) handler).getSADValidator().setAllowedClockSkew(
          this.getValidationConfig().getAllowedClockSkew());      
    }
    else {
      handler = new DefaultSamlAuthenticationHandler(authnRequestGenerator, responseProcessor, metadataProvider,
          entityDescriptorContainer, config.getSpPaths());
    }
    handler.setPreferredBindingUri(preferredRequestBinding);
    return handler;
  }

  /**
   * Based on the configuration an {@link EntityDescriptor} is created.
   *
   * @param config the SAML configuration
   * @param beanLoader the bean loader
   * @return an EntityDescriptor for the SP metadata
   */
  protected EntityDescriptor createEntityDescriptor(
      @Nonnull final SamlAuthenticationHandlerConfiguration config,
      @Nullable final BeanLoader beanLoader) {

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
        extensions.getUnknownXMLObjects()
            .add(
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
        builder.contactPersons(mdConfig.getContactPersons()
            .entrySet()
            .stream()
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
      desc.setWantAssertionsSigned(config.getRequireSignedAssertions());

      // Is AuthnRequest messages signed?
      desc.setAuthnRequestsSigned(Optional.ofNullable(config.getSignAuthnRequests()).orElse(true));

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
        final PkiCredential cred = config.getSignatureCredential().resolvePkiCredential(beanLoader);
        keyDescriptors.add(KeyDescriptorBuilder.builder()
            .use(UsageType.SIGNING)
            .keyName(cred.getName())
            .certificate(cred.getCertificate())
            .build());
      }
      if (config.getDecryptionCredential() != null) {
        final PkiCredential cred = config.getDecryptionCredential().resolvePkiCredential(beanLoader);
        keyDescriptors.add(KeyDescriptorBuilder.builder()
            .use(UsageType.ENCRYPTION)
            .keyName(cred.getName())
            .certificate(cred.getCertificate())
            .build());
        // TODO: Support for EncryptionMethod
      }
      if (config.getDefaultCredential() != null && keyDescriptors.size() < 2) {
        final PkiCredential cred = config.getDefaultCredential().resolvePkiCredential(beanLoader);
        keyDescriptors.add(KeyDescriptorBuilder.builder()
            .use(UsageType.UNSPECIFIED)
            .keyName(cred.getName())
            .certificate(cred.getCertificate())
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
    catch (final SAMLObjectBuilderRuntimeException e) {
      throw new IllegalArgumentException("Failed to set up SP metadata", e);
    }
  }

  /**
   * Based on the SAML configuration and the metadata provider a {@link ResponseProcessor} is created.
   *
   * @param config the SAML configuration
   * @param beanLoader the bean loader
   * @param metadataProvider the metadata provider
   * @return a ResponseProcessor
   */
  @Nonnull
  protected ResponseProcessor createResponseProcessor(
      @Nonnull final SamlAuthenticationHandlerConfiguration config,
      @Nullable final BeanLoader beanLoader,
      @Nonnull final MetadataProvider metadataProvider) {

    if (config.getMessageReplayChecker() != null && config.getMessageReplayCheckerRef() != null) {
      throw new IllegalArgumentException("message-replay-checker and message-replay-checker-ref can not both be set");
    }
    se.swedenconnect.signservice.storage.MessageReplayChecker messageReplayChecker;
    if (config.getMessageReplayCheckerRef() != null) {
      if (beanLoader == null) {
        throw new IllegalArgumentException("message-replay-checker-ref can not be loaded - missing bean loader");
      }
      messageReplayChecker =
          beanLoader.load(config.getMessageReplayCheckerRef(),
              se.swedenconnect.signservice.storage.MessageReplayChecker.class);
    }
    else if (config.getMessageReplayChecker() != null) {
      messageReplayChecker = config.getMessageReplayChecker();
    }
    else {
      throw new IllegalArgumentException("message-replay-checker or message-replay-checker-ref is missing");
    }

    SAMLObjectDecrypter objectDecrypter = null;
    if (config.getDecryptionCredential() != null || config.getDefaultCredential() != null) {
      final OpenSamlCredential cred = new OpenSamlCredential(config.getDecryptionCredential() != null
          ? config.getDecryptionCredential().resolvePkiCredential(beanLoader)
          : config.getDefaultCredential().resolvePkiCredential(beanLoader));
      objectDecrypter = new SAMLObjectDecrypter(cred);
    }
    if (Optional.ofNullable(config.getRequireEncryptedAssertions()).orElse(true) && objectDecrypter == null) {
      throw new IllegalArgumentException("No decryption (or default) credential specified - "
          + "required since require-encrypted-assertions is true");
    }

    return this.createResponseProcessor(config, objectDecrypter,
        new MessageReplayCheckerWrapper(messageReplayChecker), metadataProvider);
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
    else {
      processor = new ResponseProcessorImpl();
    }
    processor.setDecrypter(decrypter);
    processor.setMessageReplayChecker(messageReplayChecker);
    processor.setMetadataResolver(metadataProvider.getMetadataResolver());
    processor.setRequireEncryptedAssertions(Optional.ofNullable(config.getRequireEncryptedAssertions()).orElse(true));

    final ResponseValidationSettings validationSettings = new ResponseValidationSettings();
    validationSettings.setAllowedClockSkew(this.getValidationConfig().getAllowedClockSkew());
    validationSettings.setMaxAgeResponse(this.getValidationConfig().getMaxMessageAge());
    if (config.getRequireSignedAssertions() != null) {
      validationSettings.setRequireSignedAssertions(config.getRequireSignedAssertions().booleanValue());
    }
    processor.setResponseValidationSettings(validationSettings);
    try {
      processor.initialize();
    }
    catch (final ComponentInitializationException e) {
      throw new IllegalArgumentException("Failed to initialize SAML response processor - " + e.getMessage(), e);
    }
    return processor;
  }

  /**
   * Based on the SAML configuration, metadata provider and SP metadata an {@link AuthnRequestGenerator} is created.
   *
   * @param config the SAML configuration
   * @param beanLoader the bean loader
   * @param metadataProvider the metadata provider
   * @param entityDescriptor the SP metadata
   * @return an AuthnRequestGenerator
   */
  @Nonnull
  protected AuthnRequestGenerator createAuthnRequestGenerator(
      @Nonnull final SamlAuthenticationHandlerConfiguration config,
      @Nullable final BeanLoader beanLoader,
      @Nonnull final MetadataProvider metadataProvider,
      @Nonnull final EntityDescriptor entityDescriptor) {

    final PkiCredential signCred = Optional.ofNullable(config.getSignatureCredential())
        .map(c -> c.resolvePkiCredential(beanLoader))
        .orElseGet(() -> {
          return Optional.ofNullable(config.getDefaultCredential())
              .map(c -> c.resolvePkiCredential(beanLoader))
              .orElse(null);
        });
    if (signCred == null && Optional.ofNullable(config.getSignAuthnRequests()).orElse(true)) {
      throw new IllegalArgumentException("No signature (or default) credential specified");
    }
    final OpenSamlCredential cred = signCred != null ? new OpenSamlCredential(signCred) : null;

    AbstractAuthnRequestGenerator generator = null;
    if (SamlAuthenticationHandlerConfiguration.SAML_TYPE_SWEDEN_CONNECT.equalsIgnoreCase(config.getSamlType())) {
      generator = new SwedishEidAuthnRequestGenerator(entityDescriptor, cred, metadataProvider.getMetadataResolver());
      try {
        final SignMessageEncrypter encrypter =
            new SignMessageEncrypter(new SAMLObjectEncrypter(metadataProvider.getMetadataResolver()));
        ((SwedishEidAuthnRequestGenerator) generator).setSignMessageEncrypter(encrypter);
      }
      catch (final ComponentInitializationException e) {
        throw new IllegalArgumentException("Failed to initialize encrypter", e);
      }
    }
    else {
      generator = new DefaultAuthnRequestGenerator(entityDescriptor, cred, metadataProvider.getMetadataResolver());
    }
    try {
      generator.initialize();
    }
    catch (final ComponentInitializationException e) {
      throw new IllegalArgumentException("Failed to initialize AuthnRequest generator", e);
    }
    return generator;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected Class<AuthenticationHandler> getHandlerType() {
    return AuthenticationHandler.class;
  }

}
