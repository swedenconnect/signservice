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
package se.swedenconnect.signservice.certificate.base.config;

import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.commons.lang.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.attributemapping.DefaultAttributeMapper;
import se.swedenconnect.signservice.certificate.attributemapping.DefaultValuePolicyChecker;
import se.swedenconnect.signservice.certificate.attributemapping.DefaultValuePolicyCheckerImpl;
import se.swedenconnect.signservice.certificate.base.AbstractKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.keyprovider.InMemoryECKeyProvider;
import se.swedenconnect.signservice.certificate.keyprovider.KeyProvider;
import se.swedenconnect.signservice.certificate.keyprovider.OnDemandInMemoryRSAKeyProvider;
import se.swedenconnect.signservice.certificate.keyprovider.StackedInMemoryRSAKeyProvider;
import se.swedenconnect.signservice.core.config.AbstractHandlerFactory;
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
      @Nonnull final HandlerConfiguration<KeyAndCertificateHandler> configuration) throws IllegalArgumentException {

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

    // Key providers
    final List<KeyProvider> keyProviders = new ArrayList<>();
    if (conf.getRsaProvider() != null) {
      if (conf.getRsaProvider().getStackSize() != null) {
        keyProviders.add(new StackedInMemoryRSAKeyProvider(
            conf.getRsaProvider().getKeySize(), conf.getRsaProvider().getStackSize()));
      }
      else {
        keyProviders.add(new OnDemandInMemoryRSAKeyProvider(conf.getRsaProvider().getKeySize()));
      }
    }
    if (conf.getEcProvider() != null) {
      keyProviders.add(new InMemoryECKeyProvider(new ECGenParameterSpec(conf.getEcProvider().getCurveName())));
    }
    if (keyProviders.isEmpty()) {
      throw new IllegalArgumentException("At least one key provider must be supplied");
    }

    // Attribute mappings
    //
    AttributeMapper attributeMapper = conf.getAttributeMapper();
    if (attributeMapper == null) {
      DefaultValuePolicyChecker checker = null;
      if (conf.getDefaultValuePolicyChecker() != null) {
        log.debug("Creating default attribute mapper using configuration for default value policy checker ...");
        checker = new DefaultValuePolicyCheckerImpl(
            conf.getDefaultValuePolicyChecker().getRules(), conf.getDefaultValuePolicyChecker().isDefaultReply());
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

    final AbstractKeyAndCertificateHandler handler = this.createKeyAndCertificateHandler(configuration, keyProviders,
        attributeMapper, algorithmRegistry, profileConfiguration);

    // Certificate type
    if (conf.getCaCertificateType() != null) {
      handler.setCaCertificateType(conf.getCaCertificateType());
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
   * @param keyProviders the key providers
   * @param attributeMapper the attribute mapper
   * @param algorithmRegistry the algorithm registry
   * @param profileConfiguration the certificate profile configuration (may be null)
   * @return a handler instance
   * @throws IllegalArgumentException for configuration errors
   */
  protected abstract AbstractKeyAndCertificateHandler createKeyAndCertificateHandler(
      @Nonnull final HandlerConfiguration<KeyAndCertificateHandler> configuration,
      @Nonnull final List<KeyProvider> keyProviders, @Nonnull final AttributeMapper attributeMapper,
      @Nonnull final AlgorithmRegistry algorithmRegistry,
      @Nullable final CertificateProfileConfiguration profileConfiguration) throws IllegalArgumentException;

}
