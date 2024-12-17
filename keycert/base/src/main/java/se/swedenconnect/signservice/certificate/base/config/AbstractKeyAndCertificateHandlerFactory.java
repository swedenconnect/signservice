/*
 * Copyright 2022-2024 Sweden Connect
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
package se.swedenconnect.signservice.certificate.base.config;

import java.util.Map;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.attributemapping.DefaultAttributeMapper;
import se.swedenconnect.signservice.certificate.attributemapping.DefaultValuePolicyChecker;
import se.swedenconnect.signservice.certificate.attributemapping.DefaultValuePolicyCheckerImpl;
import se.swedenconnect.signservice.certificate.base.AbstractKeyAndCertificateHandler;
import se.swedenconnect.signservice.core.config.AbstractHandlerFactory;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Abstract base class for a {@link KeyAndCertificateHandler} factory.
 */
@Slf4j
public abstract class AbstractKeyAndCertificateHandlerFactory extends AbstractHandlerFactory<KeyAndCertificateHandler> {

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected KeyAndCertificateHandler createHandler(
      @Nonnull final HandlerConfiguration<KeyAndCertificateHandler> configuration,
      @Nullable final BeanLoader beanLoader) throws IllegalArgumentException {

    if (configuration == null) {
      throw new IllegalArgumentException("Missing configuration");
    }
    if (!AbstractKeyAndCertificateHandlerConfiguration.class.isInstance(configuration)) {
      throw new IllegalArgumentException(
          "Unknown configuration object supplied - " + configuration.getClass().getSimpleName());
    }
    final AbstractKeyAndCertificateHandlerConfiguration conf =
        AbstractKeyAndCertificateHandlerConfiguration.class.cast(configuration);

    // Algorithm registry
    //
    final AlgorithmRegistry algorithmRegistry =
        Optional.ofNullable(conf.getAlgorithmRegistry()).orElseGet(() -> AlgorithmRegistrySingleton.getInstance());

    // Credential provider
    //
    final PkiCredentialContainer keyProvider;
    if (StringUtils.isNotBlank(conf.getKeyProviderRef())) {
      if (conf.getKeyProvider() != null) {
        throw new IllegalArgumentException("Both key-provider and key-provider-ref are present, only one can appear");
      }
      if (beanLoader == null) {
        throw new IllegalArgumentException("key-provider-ref is assigned, but no bean loader is available");
      }
      keyProvider = beanLoader.load(conf.getKeyProviderRef(), PkiCredentialContainer.class);
    }
    else {
      CredentialContainerConfiguration keyProviderConfig = conf.getKeyProvider();
      if (keyProviderConfig == null) {
        // Use the defaults ...
        keyProviderConfig = new CredentialContainerConfiguration();
      }
      keyProvider = keyProviderConfig.create();
    }

    // Attribute mappings
    //
    AttributeMapper attributeMapper = conf.getAttributeMapper();
    if (attributeMapper == null) {
      DefaultValuePolicyChecker checker = null;
      if (conf.getDefaultValuePolicyChecker() != null) {
        log.debug("Creating default attribute mapper using configuration for default value policy checker ...");
        checker = new DefaultValuePolicyCheckerImpl(
            conf.getDefaultValuePolicyChecker().getRules(),
            Optional.ofNullable(conf.getDefaultValuePolicyChecker().getDefaultReply()).orElse(false));
      }
      else {
        log.info("No attribute mapper and no default value policy checker configuration present " +
            "- will create default attribute mapper that does not allow default values");
        checker = (a, r, v) -> false;
      }
      attributeMapper = new DefaultAttributeMapper(checker);
    }
    else if (conf.getDefaultValuePolicyChecker() != null) {
      log.warn("Configured default value policy checker will be ignored since an AttributeMapper was supplied");
    }

    // Certificate profile configuration
    //
    final CertificateProfileConfiguration profileConfiguration =
        Optional.ofNullable(conf.getProfileConfiguration()).orElse(null);

    final AbstractKeyAndCertificateHandler handler = this.createKeyAndCertificateHandler(
        configuration, beanLoader, keyProvider, conf.getAlgorithmKeyType(),
        attributeMapper, algorithmRegistry, profileConfiguration);

    // Certificate type
    if (conf.getCaSupportedCertificateTypes() != null) {
      handler.setCaSupportedCertificateTypes(conf.getCaSupportedCertificateTypes());
    }

    // Handler name
    if (StringUtils.isNotBlank(conf.getName())) {
      handler.setName(conf.getName());
    }

    // Service name
    if (StringUtils.isNotBlank(conf.getServiceName())) {
      handler.setServiceName(conf.getServiceName());
    }

    return handler;
  }

  /**
   * Creates a handler.
   * <p>
   * Note that the handler name, certificate type and service name does not have to be assigned. This is done by the
   * main method.
   * </p>
   *
   * @param configuration the handler configuration
   * @param beanLoader the bean loader (may be null)
   * @param credentialContainer the key generation container
   * @param algorithmKeyTypes the mapping between key types and key generation strings
   * @param attributeMapper the attribute mapper
   * @param algorithmRegistry the algorithm registry
   * @param profileConfiguration the certificate profile configuration (may be null)
   * @return a handler instance
   * @throws IllegalArgumentException for configuration errors
   */
  protected abstract AbstractKeyAndCertificateHandler createKeyAndCertificateHandler(
      @Nonnull final HandlerConfiguration<KeyAndCertificateHandler> configuration,
      @Nullable final BeanLoader beanLoader,
      @Nonnull final PkiCredentialContainer credentialContainer,
      @Nullable final Map<String, String> algorithmKeyTypes,
      @Nonnull final AttributeMapper attributeMapper,
      @Nonnull final AlgorithmRegistry algorithmRegistry,
      @Nullable final CertificateProfileConfiguration profileConfiguration) throws IllegalArgumentException;

  /** {@inheritDoc} */
  @Nonnull
  @Override
  protected Class<KeyAndCertificateHandler> getHandlerType() {
    return KeyAndCertificateHandler.class;
  }

}
