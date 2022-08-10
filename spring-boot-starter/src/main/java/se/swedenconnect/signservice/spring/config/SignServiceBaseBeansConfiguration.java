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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.Setter;
import se.swedenconnect.security.credential.converters.PropertyToX509CertificateConverter;
import se.swedenconnect.signservice.audit.actuator.ActuatorAuditLoggerFactory;
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
   * Creates the {@link HandlerFactoryRegistry} bean that is needed for handler configuration and creation.
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
  @Bean
  @ConfigurationPropertiesBinding
  public PropertyToX509CertificateConverter propertyToX509CertificateConverter() {
    return new PropertyToX509CertificateConverter();
  }

}
