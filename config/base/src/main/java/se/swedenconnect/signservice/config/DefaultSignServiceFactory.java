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
package se.swedenconnect.signservice.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.signservice.application.DefaultSignServiceEngineManager;
import se.swedenconnect.signservice.application.SignServiceEngineManager;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.base.AbstractAuditLoggerConfiguration;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.config.audit.AuditLoggerConfigurationProperties;
import se.swedenconnect.signservice.config.common.CommonBeansConfigurationProperties;
import se.swedenconnect.signservice.core.SignServiceHandler;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerFactory;
import se.swedenconnect.signservice.core.config.HandlerFactoryRegistry;
import se.swedenconnect.signservice.core.config.ValidationConfiguration;
import se.swedenconnect.signservice.engine.DefaultSignRequestMessageVerifier;
import se.swedenconnect.signservice.engine.DefaultSignServiceEngine;
import se.swedenconnect.signservice.engine.SignServiceEngine;
import se.swedenconnect.signservice.engine.config.DefaultEngineConfiguration;
import se.swedenconnect.signservice.protocol.ProtocolHandler;
import se.swedenconnect.signservice.signature.SignatureHandler;
import se.swedenconnect.signservice.storage.MessageReplayChecker;
import se.swedenconnect.signservice.storage.impl.DefaultMessageReplayChecker;
import se.swedenconnect.signservice.storage.impl.InMemoryReplayCheckerStorageContainer;
import se.swedenconnect.signservice.storage.impl.ReplayCheckerStorageContainer;

/**
 * Default implementation of the {@link SignServiceFactory} interface.
 */
@Slf4j
public class DefaultSignServiceFactory implements SignServiceFactory {

  /** The bean name used if the factory creates and registers a {@link MessageReplayChecker} bean. */
  public static final String MESSAGE_REPLAY_CHECKER_BEAN_NAME = "signservice.MessageReplayChecker";

  /** The handler factory registry. */
  private final HandlerFactoryRegistry handlerFactoryRegistry;

  /** If no BeanRegistrator is provided, any common beans will be placed in this map. */
  private final Map<String, Object> commonBeansRegistry = new HashMap<>();

  /**
   * Default constructor.
   */
  public DefaultSignServiceFactory() {
    this(null);
  }

  /**
   * Constructor accepting a {@link HandlerFactoryRegistry} that may have been prepared with specific factory
   * implementions. If none is provided a fresh {@link HandlerFactoryRegistry} object will be created.
   *
   * @param handlerFactoryRegistry handler factory registry, or null
   */
  public DefaultSignServiceFactory(@Nullable final HandlerFactoryRegistry handlerFactoryRegistry) {
    this.handlerFactoryRegistry = Optional.ofNullable(handlerFactoryRegistry)
        .orElseGet(() -> new HandlerFactoryRegistry());
  }

  /** {@inheritDoc} */
  @Override
  public SignServiceEngineManager createSignServiceEngineManager(
      @Nonnull final SignServiceConfigurationProperties configuration,
      @Nullable final BeanLoader beanLoader,
      @Nullable final BeanRegistrator beanRegistrator) throws Exception {

    // Setup the bean handlers ...
    //
    final BeanLoader bLoader = new BeanLoaderWrapper(beanLoader);
    final BeanRegistrator bRegistrator = new BeanRegistratorWrapper(beanRegistrator);

    // Validation configuration ...
    //
    final ValidationConfiguration validationConfig = Optional.ofNullable(configuration.getValidationConfig())
        .orElseGet(() -> {
          final ValidationConfiguration config = new ValidationConfiguration();
          config.init();
          return config;
        });

    // Handle the default credential ...
    //
    final PkiCredential defaultCredential = Optional.ofNullable(configuration.getDefaultCredential())
        .map(c -> c.resolvePkiCredential(beanLoader))
        .orElse(null);

    // Message replay checker ...
    //
    MessageReplayChecker messageReplayChecker = null;
    if (configuration.getMessageReplayCheckerBeanName() != null) {
      log.info("Loading bean {} ...", configuration.getMessageReplayCheckerBeanName());
      messageReplayChecker = bLoader.load(configuration.getMessageReplayCheckerBeanName(), MessageReplayChecker.class);
    }
    else {
      ReplayCheckerStorageContainer storageContainer = null;
      if (configuration.getReplayCheckerStorageContainerBeanName() != null) {
        log.info("Loading bean {} ...", configuration.getReplayCheckerStorageContainerBeanName());
        storageContainer =
            bLoader.load(configuration.getReplayCheckerStorageContainerBeanName(), ReplayCheckerStorageContainer.class);
      }
      else {
        log.info("No ReplayCheckerStorageContainer bean provided, using InMemoryReplayCheckerStorageContainer");
        storageContainer = new InMemoryReplayCheckerStorageContainer("replay-storage");
      }
      log.info("No MessageReplayChecker bean provided, using DefaultMessageReplayChecker");
      messageReplayChecker = new DefaultMessageReplayChecker(storageContainer);

      // Finally, register this bean ...
      //
      log.info("Registering MessageReplayChecker bean with name '{}'", MESSAGE_REPLAY_CHECKER_BEAN_NAME);
      bRegistrator.registerBean(
          MESSAGE_REPLAY_CHECKER_BEAN_NAME, MessageReplayChecker.class, messageReplayChecker);
    }

    // System audit logger
    //
    final AuditLogger systemAuditLogger = this.getSystemAuditLogger(configuration.getSystemAudit(), bLoader);

    // Register common beans (if present).
    //
    if (configuration.getCommonBeans() != null) {
      this.loadCommonBeans(configuration.getCommonBeans(), bLoader, bRegistrator);
    }

    // Setup the engines ...
    //
    final List<SignServiceEngine> engines = new ArrayList<>();
    for (final EngineConfigurationProperties ecp : configuration.getEngines()) {
      log.debug("Setting up engine '{}' ...", ecp.getName());

      // Should have been invoked already, but let's make sure that all is ok ...
      ecp.afterPropertiesSet();

      final DefaultEngineConfiguration conf = new DefaultEngineConfiguration();
      conf.setName(ecp.getName());

      if (StringUtils.hasText(ecp.getSignServiceId())) {
        conf.setSignServiceId(ecp.getSignServiceId());
      }
      else if (StringUtils.hasText(configuration.getDefaultSignServiceId())) {
        conf.setSignServiceId(configuration.getDefaultSignServiceId());
      }
      else {
        throw new IllegalArgumentException("No sign-service-id given for engine (and missing default-sign-service-id)");
      }
      conf.setSignServiceCredential(Optional.ofNullable(ecp.getCredential())
          .map(c -> c.resolvePkiCredential(bLoader))
          .orElse(defaultCredential));
      if (conf.getSignServiceCredential() == null) {
        throw new IllegalArgumentException(
            String.format("Could not create an engine for '%s' - no credential configured", ecp.getName()));
      }
      conf.setProcessingPaths(ecp.getProcessingPaths());

      // Client
      //
      conf.setClientConfiguration(ecp.getClient());

      // Protocol handler
      //
      final HandlerConfiguration<ProtocolHandler> protocolConf = ecp.getProtocol().getHandlerConfiguration();
      if (protocolConf.needsDefaultConfigResolving()) {
        protocolConf.resolveDefaultConfigRef(this.getResolver("protocol",
            Optional.ofNullable(configuration.getDefaultHandlerConfig())
                .map(SharedHandlerConfigurationProperties::getProtocol)
                .orElse(null)));
      }
      protocolConf.init();

      final HandlerFactory<ProtocolHandler> protocolFactory =
          this.handlerFactoryRegistry.getFactory(protocolConf.getFactoryClass());
      conf.setProtocolHandler(protocolFactory.create(protocolConf, bLoader));

      // Signature handler
      final HandlerConfiguration<SignatureHandler> sigHandlerConf = ecp.getSign().getHandlerConfiguration();
      if (sigHandlerConf.needsDefaultConfigResolving()) {
        sigHandlerConf.resolveDefaultConfigRef(this.getResolver("sign",
            Optional.ofNullable(configuration.getDefaultHandlerConfig())
                .map(SharedHandlerConfigurationProperties::getSign)
                .orElse(null)));
      }
      sigHandlerConf.init();

      final HandlerFactory<SignatureHandler> sigHandlerFactory =
          this.handlerFactoryRegistry.getFactory(sigHandlerConf.getFactoryClass());
      conf.setSignatureHandler(sigHandlerFactory.create(sigHandlerConf, bLoader));

      // Key and certificate handler
      final HandlerConfiguration<KeyAndCertificateHandler> keyAndCertConf = ecp.getCert().getHandlerConfiguration();
      if (keyAndCertConf.needsDefaultConfigResolving()) {
        keyAndCertConf.resolveDefaultConfigRef(this.getResolver("cert",
            Optional.ofNullable(configuration.getDefaultHandlerConfig())
                .map(SharedHandlerConfigurationProperties::getCert)
                .orElse(null)));
      }
      keyAndCertConf.init();

      final HandlerFactory<KeyAndCertificateHandler> keyAndCertHandlerFactory =
          this.handlerFactoryRegistry.getFactory(keyAndCertConf
              .getFactoryClass());
      conf.setKeyAndCertificateHandler(keyAndCertHandlerFactory.create(keyAndCertConf, bLoader));

      // Audit logger
      //
      final HandlerConfiguration<AuditLogger> auditConf = ecp.getAudit().getHandlerConfiguration();
      if (auditConf.needsDefaultConfigResolving()) {
        auditConf.resolveDefaultConfigRef(this.getResolver("audit",
            Optional.ofNullable(configuration.getDefaultHandlerConfig())
                .map(SharedHandlerConfigurationProperties::getAudit)
                .orElse(null)));
      }
      if (AbstractAuditLoggerConfiguration.class.isInstance(auditConf)) {
        final AbstractAuditLoggerConfiguration _auditConf = AbstractAuditLoggerConfiguration.class.cast(auditConf);
        if (_auditConf.getPrincipal() == null) {
          _auditConf.setPrincipal(ecp.getClient().getClientId());
        }
      }
      auditConf.init();

      final HandlerFactory<AuditLogger> auditFactory =
          this.handlerFactoryRegistry.getFactory(auditConf.getFactoryClass());
      conf.setAuditLogger(auditFactory.create(auditConf, bLoader));

      // Authentication handler
      //
      final HandlerConfiguration<AuthenticationHandler> authnConf = ecp.getAuthn().getHandlerConfiguration();
      if (authnConf.needsDefaultConfigResolving()) {
        authnConf.resolveDefaultConfigRef(this.getResolver("authn",
            Optional.ofNullable(configuration.getDefaultHandlerConfig())
                .map(SharedHandlerConfigurationProperties::getAuthn)
                .orElse(null)));
      }
      authnConf.init();

      final HandlerFactory<AuthenticationHandler> authnFactory =
          this.handlerFactoryRegistry.getFactory(authnConf.getFactoryClass());
      conf.setAuthenticationHandler(authnFactory.create(authnConf, bLoader));

      conf.init();

      final DefaultSignServiceEngine engine =
          new DefaultSignServiceEngine(conf, messageReplayChecker, systemAuditLogger);
      final DefaultSignRequestMessageVerifier verifier = new DefaultSignRequestMessageVerifier();
      verifier.setAllowedClockSkew(validationConfig.getAllowedClockSkew());
      verifier.setMaxMessageAge(validationConfig.getMaxMessageAge());
      engine.setSignRequestMessageVerifier(verifier);
      engine.init();

      engines.add(engine);
    }
    if (engines.isEmpty()) {
      throw new IllegalArgumentException("No engines configured");
    }

    return new DefaultSignServiceEngineManager(engines, systemAuditLogger);
  }

  /**
   * Loads any commons beans declared in the SignService configuration.
   *
   * @param props the common beans configuration
   * @param beanLoader the bean loader
   * @param beanRegistrator the bean registrator
   * @throws Exception for configuration errors
   */
  protected void loadCommonBeans(@Nonnull final CommonBeansConfigurationProperties props,
      @Nonnull final BeanLoader beanLoader, @Nonnull final BeanRegistrator beanRegistrator) throws Exception {

    if (props.getSaml() != null && props.getSaml().getMetadataProvider() != null) {
      log.debug("Registering '{}' bean ...", props.getSaml().getMetadataProvider().getBeanName());
      beanRegistrator.registerBean(props.getSaml().getMetadataProvider().getBeanName(),
          MetadataProvider.class, props.getSaml().getMetadataProvider().create());
    }

    if (props.getProtocol() != null) {
      final HandlerConfiguration<ProtocolHandler> protocolConf = props.getProtocol().getHandlerConfiguration();
      if (protocolConf.needsDefaultConfigResolving()) {
        throw new IllegalArgumentException(
            "Bad configuration for signservice.common-beans.protocol - No merge resolving is possible for bean instantiation");
      }
      protocolConf.init();

      final HandlerFactory<ProtocolHandler> protocolFactory =
          this.handlerFactoryRegistry.getFactory(protocolConf.getFactoryClass());

      log.debug("Registering '{}' bean ...", props.getProtocol().getBeanName());
      beanRegistrator.registerBean(props.getProtocol().getBeanName(), ProtocolHandler.class,
          protocolFactory.create(protocolConf, beanLoader));
    }

    if (props.getSign() != null) {
      final HandlerConfiguration<SignatureHandler> sigHandlerConf = props.getSign().getHandlerConfiguration();
      if (sigHandlerConf.needsDefaultConfigResolving()) {
        throw new IllegalArgumentException(
            "Bad configuration for signservice.common-beans.sign - No merge resolving is possible for bean instantiation");
      }
      sigHandlerConf.init();

      final HandlerFactory<SignatureHandler> sigHandlerFactory =
          this.handlerFactoryRegistry.getFactory(sigHandlerConf.getFactoryClass());

      log.debug("Registering '{}' bean ...", props.getSign().getBeanName());
      beanRegistrator.registerBean(props.getSign().getBeanName(), SignatureHandler.class,
          sigHandlerFactory.create(sigHandlerConf, beanLoader));
    }

    if (props.getKeyProvider() != null) {
      log.debug("Registering '{}' bean ...", props.getKeyProvider().getBeanName());
      beanRegistrator.registerBean(props.getKeyProvider().getBeanName(), PkiCredentialContainer.class,
          props.getKeyProvider().create());
    }

    if (props.getCert() != null) {
      final HandlerConfiguration<KeyAndCertificateHandler> keyAndCertConf = props.getCert().getHandlerConfiguration();
      if (keyAndCertConf.needsDefaultConfigResolving()) {
        throw new IllegalArgumentException(
            "Bad configuration for signservice.common-beans.cert - No merge resolving is possible for bean instantiation");
      }
      keyAndCertConf.init();

      final HandlerFactory<KeyAndCertificateHandler> keyAndCertHandlerFactory =
          this.handlerFactoryRegistry.getFactory(keyAndCertConf.getFactoryClass());

      log.debug("Registering '{}' bean ...", props.getCert().getBeanName());
      beanRegistrator.registerBean(props.getCert().getBeanName(), KeyAndCertificateHandler.class,
          keyAndCertHandlerFactory.create(keyAndCertConf, beanLoader));
    }

  }

  /**
   * Gets the system {@link AuditLogger} from the configuration.
   *
   * @param props the system audit logger properties
   * @param beanLoader the bean loader
   * @return an AuditLogger
   * @throws Exception for configuration errors
   */
  protected AuditLogger getSystemAuditLogger(
      @Nullable final AuditLoggerConfigurationProperties props, @Nonnull final BeanLoader beanLoader) throws Exception {
    if (props == null) {
      throw new IllegalArgumentException("Missing system audit logger configuration (signservice.system-audit.*)");
    }
    final HandlerConfiguration<AuditLogger> auditConf = props.getHandlerConfiguration();
    if (auditConf.needsDefaultConfigResolving()) {
      throw new IllegalArgumentException("signservice.system-audit.* incorrectly configured");
    }
    auditConf.init();
    final HandlerFactory<AuditLogger> auditFactory =
        this.handlerFactoryRegistry.getFactory(auditConf.getFactoryClass());
    return auditFactory.create(auditConf, beanLoader);
  }

  /**
   * Helper method for resolving default configurations.
   *
   * @param <T> the handler type
   * @param prefix the prefix to look for in the configuration
   * @param defaultConfig the default configuration
   * @return a function for resolving
   */
  private <T extends SignServiceHandler> Function<String, HandlerConfiguration<T>> getResolver(
      @Nonnull final String prefix, @Nullable final HandlerConfigurationProperties<T> defaultConfig) {
    return ref -> {
      if (!ref.startsWith(prefix + ".")) {
        throw new IllegalArgumentException("Unknown default configuration reference: " + ref);
      }
      final String handlerRef = ref.substring(prefix.length() + 1);
      return Optional.ofNullable(defaultConfig)
          .map(c -> c.getHandlerConfiguration(handlerRef))
          .orElse(null);
    };
  }

  /**
   * A {@link BeanRegistrator} that wraps the instance provided in the call to
   * {@link DefaultSignServiceFactory#createSignServiceEngineManager(SignServiceConfigurationProperties, BeanLoader, BeanRegistrator)}.
   */
  private class BeanRegistratorWrapper implements BeanRegistrator {

    /** The wrapped bean registrator. */
    private final BeanRegistrator beanRegistrator;

    /**
     * Constructor.
     *
     * @param beanRegistrator the bean registrator
     */
    public BeanRegistratorWrapper(@Nonnull final BeanRegistrator beanRegistrator) {
      this.beanRegistrator = beanRegistrator;
    }

    /** {@inheritDoc} */
    @Override
    public <T> void registerBean(@Nonnull final String beanName, @Nonnull final Class<T> type, @Nonnull final T bean)
        throws Exception {
      if (beanRegistrator == null) {
        commonBeansRegistry.put(beanName, bean);
      }
      else {
        this.beanRegistrator.registerBean(beanName, type, bean);
      }
    }

  }

  /**
   * The bean loader we use. It wraps the loader provided to the factory and has the extension that it can also read
   * "beans" from the local common beans registry. This will be used if no {@link BeanRegistrator} is provided to the
   * factory.
   */
  private class BeanLoaderWrapper implements BeanLoader {

    /** The wrapped loader (may be null). */
    private final BeanLoader beanLoader;

    /**
     * Constructor.
     *
     * @param beanLoader the actual bean loader
     */
    public BeanLoaderWrapper(@Nonnull final BeanLoader beanLoader) {
      this.beanLoader = beanLoader;
    }

    /** {@inheritDoc} */
    @Override
    public <T> T load(@Nonnull final String beanName, @Nonnull final Class<T> type) {
      if (commonBeansRegistry.containsKey(beanName)) {
        return type.cast(commonBeansRegistry.get(beanName));
      }
      else if (this.beanLoader == null) {
        throw new IllegalArgumentException(String.format("Can not load bean '%s' - No bean loader provided", beanName));
      }
      else {
        return this.beanLoader.load(beanName, type);
      }
    }

  }

}
