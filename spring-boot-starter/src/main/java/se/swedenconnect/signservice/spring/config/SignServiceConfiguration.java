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
package se.swedenconnect.signservice.spring.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.actuate.audit.AuditEventRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.util.StringUtils;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialFactoryBean;
import se.swedenconnect.signservice.api.engine.DefaultSignServiceEngine;
import se.swedenconnect.signservice.api.engine.config.impl.DefaultEngineConfiguration;
import se.swedenconnect.signservice.application.SignServiceEngineManager;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.base.AbstractAuditLoggerConfiguration;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.core.SignServiceHandler;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerFactory;
import se.swedenconnect.signservice.core.config.HandlerFactoryRegistry;
import se.swedenconnect.signservice.core.config.spring.SpringBeanLoader;
import se.swedenconnect.signservice.engine.SignServiceEngine;
import se.swedenconnect.signservice.protocol.ProtocolHandler;
import se.swedenconnect.signservice.session.SessionHandler;
import se.swedenconnect.signservice.session.impl.DefaultSessionHandler;
import se.swedenconnect.signservice.signature.SignatureHandler;
import se.swedenconnect.signservice.spring.config.engine.EngineConfigurationProperties;
import se.swedenconnect.signservice.storage.MessageReplayChecker;
import se.swedenconnect.signservice.storage.impl.DefaultMessageReplayChecker;
import se.swedenconnect.signservice.storage.impl.InMemoryReplayCheckerStorageContainer;
import se.swedenconnect.signservice.storage.impl.ReplayCheckerStorageContainer;

/**
 * Main configuration for SignService.
 */
@Configuration
@EnableConfigurationProperties(SignServiceConfigurationProperties.class)
@DependsOn("openSAML")
@Slf4j
public class SignServiceConfiguration {

  /** The application context. */
  @Setter
  @Autowired
  private ConfigurableApplicationContext applicationContext;

  /** The SignService configuration properties. */
  @Setter
  @Autowired
  private SignServiceConfigurationProperties properties;

  /** The registry bean for factories. */
  @Setter
  @Autowired
  private HandlerFactoryRegistry handlerFactoryRegistry;

  @Setter
  @Autowired(required = false)
  private AuditEventRepository auditEventRepository;

  /**
   * Creates the {@code signservice.Domain} bean representing the domain under which the IdP is running.
   *
   * @return the domain
   */
  @ConditionalOnMissingBean(name = "signservice.Domain")
  @Bean("signservice.Domain")
  public String domain() {
    return this.properties.getDomain();
  }

  /**
   * Creates the {@code signservice.BaseUrl} bean representing the IdP "base URL", i.e., the protocol, domain and
   * context path.
   *
   * @return the base URL
   */
  @ConditionalOnMissingBean(name = "signservice.BaseUrl")
  @Bean("signservice.BaseUrl")
  public String baseUrl() {
    return this.properties.getBaseUrl();
  }

  /**
   * If a SignService default credential has been configured, this is created.
   *
   * @return a PkiCredential or null
   * @throws Exception
   *           for init errors
   */
  @ConditionalOnMissingBean(name = "signservice.DefaultCredential")
  @Bean("signservice.DefaultCredential")
  public PkiCredential defaultCredential() throws Exception {
    if (this.properties.getDefaultCredential() != null) {
      final PkiCredentialFactoryBean credentialFactory = new PkiCredentialFactoryBean(this.properties.getDefaultCredential());
      credentialFactory.afterPropertiesSet();
      return credentialFactory.getObject();
    }
    else {
      // No default credential has been configured - this is perfectly ok
      return null;
    }
  }

  /**
   * Gets the system audit logger bean.
   *
   * @return the system audit logger bean
   * @throws Exception
   *           for init errors
   */
  @ConditionalOnMissingBean(name = "signservice.SystemAuditLogger")
  @Bean("signservice.SystemAuditLogger")
  public AuditLogger systemAuditLogger() throws Exception {
    final HandlerConfiguration<AuditLogger> auditConf = this.properties.getSystemAudit().getHandlerConfiguration();
    if (auditConf.needsDefaultConfigResolving()) {
      throw new IllegalArgumentException("signservice.system-audit.* incorrectly configured");
    }
    auditConf.init();

    final HandlerFactory<AuditLogger> auditFactory = this.handlerFactoryRegistry.getFactory(auditConf.getFactoryClass());
    return auditFactory.create(auditConf);
  }

  /**
   * If no {@link SessionHandler} bean has been defined, a {@link DefaultSessionHandler} object will be created. This
   * handler is backed by a {@link HttpSession}.
   *
   * @return session handler bean
   */
  @ConditionalOnMissingBean
  @Bean("signservice.SessionHandler")
  public SessionHandler sessionHandler() {
    return new DefaultSessionHandler();
  }

  @ConditionalOnMissingBean(name = "signservice.MessageReplayChecker")
  @Bean("signservice.MessageReplayChecker")
  public MessageReplayChecker messageReplayChecker(final ReplayCheckerStorageContainer replayStorage) {
    return new DefaultMessageReplayChecker(replayStorage != null
      ? replayStorage
      : new InMemoryReplayCheckerStorageContainer("replay-storage"));
  }

  /**
   * Creates the {@link SignServiceEngineManager} bean.
   *
   * @param engines
   *          the engines
   * @param systemAuditLogger
   *          the system audit logger
   * @return a SignServiceEngineManager bean
   */
  @ConditionalOnMissingBean
  @Bean("signservice.SignServiceEngineManager")
  public SignServiceEngineManager signServiceEngineManager(
      @Qualifier("signservice.Engines") final List<SignServiceEngine> engines,
      @Qualifier("signservice.SystemAuditLogger") final AuditLogger systemAuditLogger) {
    return new SignServiceEngineManager(engines, systemAuditLogger);
  }

  @ConditionalOnMissingBean(name = "signservice.Engines")
  @Bean("signservice.Engines")
  public List<SignServiceEngine> engines(
      @Qualifier("signservice.SessionHandler") final SessionHandler sessionHandler,
      @Qualifier("signservice.MessageReplayChecker") final MessageReplayChecker messageReplayChecker,
      @Qualifier("signservice.DefaultCredential") final PkiCredential defaultCredential,
      @Qualifier("signservice.SystemAuditLogger") final AuditLogger systemAuditLogger) throws Exception {

    final SpringBeanLoader beanLoader = new SpringBeanLoader(this.applicationContext);

    //
    // First register common beans (if any)
    //
    final CommonBeansConfigurationProperties commons = this.properties.getCommonBeans();
    if (commons != null) {
      final ConfigurableListableBeanFactory beanFactory = this.applicationContext.getBeanFactory();

      if (commons.getSaml() != null) {
        if (commons.getSaml().getMetadataProvider() != null) {
          log.debug("Registering '{}' bean ...", commons.getSaml().getMetadataProvider().getBeanName());
          beanFactory.registerSingleton(commons.getSaml().getMetadataProvider().getBeanName(),
            commons.getSaml().getMetadataProvider().create());
        }
      }

      if (commons.getProtocol() != null) {
        final HandlerConfiguration<ProtocolHandler> protocolConf = commons.getProtocol().getHandlerConfiguration();
        if (protocolConf.needsDefaultConfigResolving()) {
          throw new IllegalArgumentException(
            "Bad configuration for signservice.common-beans.protocol - No merge resolving is possible for bean instantiation");
        }
        protocolConf.init();

        final HandlerFactory<ProtocolHandler> protocolFactory = this.handlerFactoryRegistry.getFactory(protocolConf.getFactoryClass());
        log.debug("Registering '{}' bean ...", commons.getProtocol().getBeanName());
        beanFactory.registerSingleton(commons.getProtocol().getBeanName(), protocolFactory.create(protocolConf, beanLoader));
      }

      if (commons.getSign() != null) {
        final HandlerConfiguration<SignatureHandler> sigHandlerConf = commons.getSign().getHandlerConfiguration();
        if (sigHandlerConf.needsDefaultConfigResolving()) {
          throw new IllegalArgumentException(
            "Bad configuration for signservice.common-beans.sign - No merge resolving is possible for bean instantiation");
        }
        sigHandlerConf.init();

        final HandlerFactory<SignatureHandler> sigHandlerFactory = this.handlerFactoryRegistry.getFactory(sigHandlerConf.getFactoryClass());
        log.debug("Registering '{}' bean ...", commons.getSign().getBeanName());
        beanFactory.registerSingleton(commons.getSign().getBeanName(), sigHandlerFactory.create(sigHandlerConf, beanLoader));
      }

      if (commons.getKeyProvider() != null) {
        log.debug("Registering '{}' bean ...", commons.getKeyProvider().getBeanName());
        beanFactory.registerSingleton(commons.getKeyProvider().getBeanName(),
            commons.getKeyProvider().create());
      }

      if (commons.getCert() != null) {
        final HandlerConfiguration<KeyAndCertificateHandler> keyAndCertConf = commons.getCert().getHandlerConfiguration();
        if (keyAndCertConf.needsDefaultConfigResolving()) {
          throw new IllegalArgumentException(
              "Bad configuration for signservice.common-beans.cert - No merge resolving is possible for bean instantiation");
        }
        keyAndCertConf.init();

        final HandlerFactory<KeyAndCertificateHandler> keyAndCertHandlerFactory =
            this.handlerFactoryRegistry.getFactory(keyAndCertConf.getFactoryClass());
        log.debug("Registering '{}' bean ...", commons.getCert().getBeanName());
        beanFactory.registerSingleton(commons.getCert().getBeanName(), keyAndCertHandlerFactory.create(keyAndCertConf, beanLoader));
      }

    }

    List<SignServiceEngine> engines = new ArrayList<>();

    for (final EngineConfigurationProperties ecp : this.properties.getEngines()) {
      log.debug("Setting up engine '{}' ...", ecp.getName());

      final DefaultEngineConfiguration conf = new DefaultEngineConfiguration();
      conf.setName(ecp.getName());

      if (StringUtils.hasText(ecp.getSignServiceId())) {
        conf.setSignServiceId(ecp.getSignServiceId());
      }
      else if (StringUtils.hasText(this.properties.getDefaultSignServiceId())) {
        conf.setSignServiceId(this.properties.getDefaultSignServiceId());
      }
      else {
        throw new IllegalArgumentException("No sign-service-id given for engine (and missing default-sign-service-id)");
      }

      if (ecp.getCredential() != null) {
        final PkiCredentialFactoryBean credentialFactory = new PkiCredentialFactoryBean(ecp.getCredential());
        credentialFactory.afterPropertiesSet();
        conf.setSignServiceCredential(credentialFactory.getObject());
      }
      else {
        if (defaultCredential == null) {
          throw new BeanCreationException(
            String.format("Could not create an engine for '%s' - no credential configured", ecp.getName()));
        }
        conf.setSignServiceCredential(defaultCredential);
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
          Optional.ofNullable(this.properties.getDefaultHandlerConfig())
            .map(SharedHandlerConfigurationProperties::getProtocol)
            .orElse(null)));
      }
      protocolConf.init();

      final HandlerFactory<ProtocolHandler> protocolFactory = this.handlerFactoryRegistry.getFactory(protocolConf.getFactoryClass());
      conf.setProtocolHandler(protocolFactory.create(protocolConf, beanLoader));

      // Signature handler
      final HandlerConfiguration<SignatureHandler> sigHandlerConf = ecp.getSign().getHandlerConfiguration();
      if (sigHandlerConf.needsDefaultConfigResolving()) {
        sigHandlerConf.resolveDefaultConfigRef(this.getResolver("sign",
          Optional.ofNullable(this.properties.getDefaultHandlerConfig())
            .map(SharedHandlerConfigurationProperties::getSign)
            .orElse(null)));
      }
      sigHandlerConf.init();

      final HandlerFactory<SignatureHandler> sigHandlerFactory = this.handlerFactoryRegistry.getFactory(sigHandlerConf.getFactoryClass());
      conf.setSignatureHandler(sigHandlerFactory.create(sigHandlerConf, beanLoader));

      // Key and certificate handler
      final HandlerConfiguration<KeyAndCertificateHandler> keyAndCertConf = ecp.getCert().getHandlerConfiguration();
      if (keyAndCertConf.needsDefaultConfigResolving()) {
        keyAndCertConf.resolveDefaultConfigRef(this.getResolver("cert",
          Optional.ofNullable(this.properties.getDefaultHandlerConfig())
            .map(SharedHandlerConfigurationProperties::getCert)
            .orElse(null)));
      }
      keyAndCertConf.init();

      final HandlerFactory<KeyAndCertificateHandler> keyAndCertHandlerFactory = this.handlerFactoryRegistry.getFactory(keyAndCertConf
        .getFactoryClass());
      conf.setKeyAndCertificateHandler(keyAndCertHandlerFactory.create(keyAndCertConf, beanLoader));

      // Audit logger
      //
      final HandlerConfiguration<AuditLogger> auditConf = ecp.getAudit().getHandlerConfiguration();
      if (auditConf.needsDefaultConfigResolving()) {
        auditConf.resolveDefaultConfigRef(this.getResolver("audit",
          Optional.ofNullable(this.properties.getDefaultHandlerConfig())
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

      final HandlerFactory<AuditLogger> auditFactory = this.handlerFactoryRegistry.getFactory(auditConf.getFactoryClass());
      conf.setAuditLogger(auditFactory.create(auditConf, beanLoader));

      // Authentication handler
      //
      final HandlerConfiguration<AuthenticationHandler> authnConf = ecp.getAuthn().getHandlerConfiguration();
      if (authnConf.needsDefaultConfigResolving()) {
        authnConf.resolveDefaultConfigRef(this.getResolver("authn",
          Optional.ofNullable(this.properties.getDefaultHandlerConfig())
            .map(SharedHandlerConfigurationProperties::getAuthn)
            .orElse(null)));
      }
      authnConf.init();

      final HandlerFactory<AuthenticationHandler> authnFactory = this.handlerFactoryRegistry.getFactory(authnConf.getFactoryClass());
      conf.setAuthenticationHandler(authnFactory.create(authnConf, beanLoader));

      conf.init();

      final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(conf, sessionHandler, messageReplayChecker, systemAuditLogger);
      engine.init();

      engines.add(engine);
    }

    return engines;
  }

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

}
