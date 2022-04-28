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

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialFactoryBean;
import se.swedenconnect.security.credential.utils.X509Utils;
import se.swedenconnect.signservice.api.engine.DefaultSignServiceEngine;
import se.swedenconnect.signservice.api.engine.config.impl.DefaultEngineConfiguration;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.AuditLoggerSingleton;
import se.swedenconnect.signservice.audit.actuator.ActuatorAuditLogger;
import se.swedenconnect.signservice.authn.AuthenticationErrorCode;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.authn.AuthenticationResultChoice;
import se.swedenconnect.signservice.authn.UserAuthenticationException;
import se.swedenconnect.signservice.client.impl.DefaultClientConfiguration;
import se.swedenconnect.signservice.engine.SignServiceEngine;
import se.swedenconnect.signservice.protocol.ProtocolHandler;
import se.swedenconnect.signservice.protocol.dss.DssProtocolHandler;
import se.swedenconnect.signservice.protocol.msg.AuthnRequirements;
import se.swedenconnect.signservice.protocol.msg.SignMessage;
import se.swedenconnect.signservice.session.SessionHandler;
import se.swedenconnect.signservice.session.SignServiceContext;
import se.swedenconnect.signservice.session.impl.DefaultSessionHandler;
import se.swedenconnect.signservice.spring.config.engine.EngineConfigurationProperties;
import se.swedenconnect.signservice.storage.MessageReplayChecker;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Main configuration for SignService.
 */
@Configuration
@EnableConfigurationProperties(SignServiceConfigurationProperties.class)
@Slf4j
public class SignServiceConfiguration {

  /** The SignService configuration properties. */
  @Setter
  @Autowired
  private SignServiceConfigurationProperties properties;

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
   * Creates the {@code signservice.BaseUrl} bean representing the IdP "base URL", i.e., everything up until the context
   * path.
   *
   * @return the base URL
   */
  @ConditionalOnMissingBean(name = "signservice.BaseUrl")
  @Bean("signservice.BaseUrl")
  public String baseUrl() {
    return this.properties.getBaseUrl();
  }

  /**
   * Creates the {@code signservice.ContextPath} bean holding the SignService context path
   * ({@code server.servlet.context-path}).
   *
   * @param contextPath the context path
   * @return the context path
   */
  @ConditionalOnMissingBean(name = "signservice.ContextPath")
  @Bean("signservice.ContextPath")
  public String contextPath(@Value("${server.servlet.context-path:/}") final String contextPath) {
    return contextPath;
  }

  /**
   * If a SignService default credential has been configured, this is created.
   *
   * @return a PkiCredential or null
   * @throws Exception for init errors
   */
  @ConditionalOnMissingBean(name = "signservice.DefaultCredential")
  @Bean("signservice.DefaultCredential")
  public PkiCredential defaultCredential() throws Exception {
    if (this.properties.getDefaultCredential() != null) {
      final PkiCredentialFactoryBean credentialFactory =
          new PkiCredentialFactoryBean(this.properties.getDefaultCredential());
      credentialFactory.afterPropertiesSet();
      return credentialFactory.getObject();
    }
    else {
      // No default credential has been configured - this is perfectly ok
      return null;
    }
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
  public MessageReplayChecker messageReplayChecker() {
    // TODO
    return null;
  }

  @Bean
  public AuditLogger auditLogger() {
    AuditLoggerSingleton.init(new ActuatorAuditLogger());
    return AuditLoggerSingleton.getAuditLogger();
  }

  // Dummy
  @Bean
  public ProtocolHandler protocolHandler() {
    return new DssProtocolHandler();
  }

  @ConditionalOnMissingBean(name = "signservice.Engines")
  @Bean("signservice.Engines")
  public List<SignServiceEngine> engines(
      @Qualifier("signservice.SessionHandler") final SessionHandler sessionHandler,
      @Qualifier("signservice.MessageReplayChecker") final MessageReplayChecker messageReplayChecker,
      @Qualifier("signservice.DefaultCredential") final PkiCredential defaultCredential) throws Exception {

    List<SignServiceEngine> engines = new ArrayList<>();

    for (final EngineConfigurationProperties ecp : this.properties.getEngines()) {
      log.debug("Setting up engine '{}' ...", ecp.getName());

      final DefaultEngineConfiguration conf = new DefaultEngineConfiguration();
      conf.setName(ecp.getName());
      conf.setSignServiceId(ecp.getSignServiceId());

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

      conf.setProtocolHandler(this.protocolHandler()); // TODO: change
      conf.setAuthenticationHandler(new MockAuthnHandler());  // TODO: change
      conf.setKeyAndCertificateHandler(null); // TODO: change
      conf.setAuditLogger(this.auditLogger()); // TODO: change

      final DefaultClientConfiguration clientConf = new DefaultClientConfiguration(ecp.getClient().getClientId());
      if (ecp.getClient().getResponseUrls() != null) {
        clientConf.setResponseUrls(ecp.getClient().getResponseUrls());
      }
      if (ecp.getClient().getCertificates() != null) {
        final List<X509Certificate> certs = new ArrayList<>();
        for (final Resource r : ecp.getClient().getCertificates()) {
          certs.add(X509Utils.decodeCertificate(r));
        }
        clientConf.setTrustedCertificates(certs);
      }
      conf.setClientConfiguration(clientConf);

//      conf.init();

      final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(conf, sessionHandler, messageReplayChecker);
      engine.init();

      engines.add(engine);
    }

    return engines;
  }

  public static class MockAuthnHandler implements AuthenticationHandler {

    @Override
    public String getName() {
      return "MockAuthnHandler";
    }

    @Override
    public AuthenticationResultChoice authenticate(AuthnRequirements authnRequirements, SignMessage signMessage,
        SignServiceContext context) throws UserAuthenticationException {
      throw new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR, "Not implemented");
    }

    @Override
    public AuthenticationResultChoice resumeAuthentication(HttpServletRequest httpRequest, SignServiceContext context)
        throws UserAuthenticationException {
      throw new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR, "Not implemented");
    }

    @Override
    public boolean canProcess(HttpServletRequest httpRequest) {
      return false;
    }

  }

}
