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

import java.security.cert.X509Certificate;

import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

import lombok.Setter;
import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;
import se.swedenconnect.opensaml.sweid.xmlsec.config.SwedishEidSecurityConfiguration;
import se.swedenconnect.security.credential.converters.PropertyToX509CertificateConverter;
import se.swedenconnect.signservice.audit.actuator.ActuatorAuditLoggerFactory;
import se.swedenconnect.signservice.authn.saml.spring.PropertyToEntityDescriptorConverter;
import se.swedenconnect.signservice.core.config.HandlerFactoryRegistry;

/**
 * Configuration of base beans for the SignService.
 */
@Configuration
public class SignServiceBaseBeansConfiguration {

  /** Needed to set up actuator audit logging. */
  @Setter
  @Autowired
  private ApplicationEventPublisher applicationEventPublisher;

  /**
   * Creates the {@link FactoryRegistry} bean that is needed for handler configuration and creation.
   *
   * @return a HandlerFactoryRegistry bean
   */
  @Bean
  public HandlerFactoryRegistry handlerFactoryRegistry() {
    final ActuatorAuditLoggerFactory actuatorFactory = new ActuatorAuditLoggerFactory();
    actuatorFactory.setPublisher(this.applicationEventPublisher);
    final HandlerFactoryRegistry factoryRegistry = new HandlerFactoryRegistry();
    // Pre-load it with the special factory used to create ActuatorAuditLogger:s.
    factoryRegistry.addFactory(actuatorFactory);
    return factoryRegistry;
  }

  /**
   * Creates the bean the allows us to use property values that are referencing certificate resources and get the
   * {@link X509Certificate} injected.
   *
   * @return a PropertyToX509CertificateConverter bean
   */
  @ConditionalOnMissingBean
  @Bean
  @ConfigurationPropertiesBinding
  public PropertyToX509CertificateConverter propertyToX509CertificateConverter() {
    return new PropertyToX509CertificateConverter();
  }

  /**
   * Creates the bean the allows us to use property values that are referencing EntityDescriptor resources and get the
   * {@link EntityDescriptor} injected.
   *
   * @return a EntityDescriptor bean
   */
  @ConditionalOnMissingBean
  @Bean
  @ConfigurationPropertiesBinding
  @DependsOn("openSAML")
  public PropertyToEntityDescriptorConverter propertyToEntityDescriptorConverter() {
    return new PropertyToEntityDescriptorConverter();
  }

  @ConditionalOnMissingBean
  @Bean
  @ConfigurationPropertiesBinding
  public LocalizedStringConverter localizedStringConverter() {
    return new LocalizedStringConverter();
  }

  /**
   * Gets the OpenSAML initializer (which is needed for SAML support)
   *
   * @return OpenSAMLInitializer
   * @throws Exception for init errors
   */
  @ConditionalOnMissingBean
  @Bean("openSAML")
  public OpenSAMLInitializer openSAML() throws Exception {
    OpenSAMLInitializer.getInstance()
        .initialize(
            new OpenSAMLSecurityDefaultsConfig(new SwedishEidSecurityConfiguration()),
            new OpenSAMLSecurityExtensionConfig());
    return OpenSAMLInitializer.getInstance();
  }

}
