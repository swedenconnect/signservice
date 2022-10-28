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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Import;

import lombok.Setter;
import se.swedenconnect.signservice.application.SignServiceEngineManager;
import se.swedenconnect.signservice.audit.actuator.ActuatorAuditLoggerFactory;
import se.swedenconnect.signservice.config.BeanRegistrator;
import se.swedenconnect.signservice.config.DefaultSignServiceFactory;
import se.swedenconnect.signservice.config.SignServiceConfigurationProperties;
import se.swedenconnect.signservice.config.SignServiceFactory;
import se.swedenconnect.signservice.config.spring.OpenSAMLConfiguration;
import se.swedenconnect.signservice.config.spring.SpringBeanRegistrator;
import se.swedenconnect.signservice.config.spring.SpringSignServiceConfigurationProperties;
import se.swedenconnect.signservice.config.spring.converters.SignServiceConverterConfiguration;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerFactoryRegistry;
import se.swedenconnect.signservice.core.config.spring.SpringBeanLoader;

/**
 * Main configuration for a SignService application.
 */
@Configuration
@Import({ OpenSAMLConfiguration.class, SignServiceConverterConfiguration.class })
@EnableConfigurationProperties(SpringSignServiceConfigurationProperties.class)
@DependsOn("openSAML")
public class SignServiceConfiguration {

  /** The application context. */
  @Setter
  @Autowired
  private ConfigurableApplicationContext applicationContext;

  /** Needed to set up actuator audit logging. */
  @Setter
  @Autowired
  private ApplicationEventPublisher applicationEventPublisher;

  /** The SignService configuration properties. */
  @Setter
  @Autowired
  private SignServiceConfigurationProperties properties;

  /**
   * Creates the {@link HandlerFactoryRegistry} bean that is needed for handler configuration and creation.
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
   * Creates the {@link SignServiceFactory} bean that we use to set up the {@link SignServiceEngineManager}.
   *
   * @param handlerFactoryRegistry handler factory registry
   * @return a SignServiceFactory bean
   */
  @ConditionalOnMissingBean
  @Bean
  public SignServiceFactory signServiceFactory(final HandlerFactoryRegistry handlerFactoryRegistry) {
    return new DefaultSignServiceFactory(handlerFactoryRegistry);
  }

  /**
   * Creates the {@link BeanLoader} that are used during setup.
   *
   * @return a BeanLoader bean
   */
  @ConditionalOnMissingBean
  @Bean
  public BeanLoader beanLoader() {
    return new SpringBeanLoader(this.applicationContext);
  }

  /**
   * Creates the {@link BeanRegistrator} that are used during setup.
   *
   * @return a BeanRegistrator bean
   */
  @Bean
  public BeanRegistrator beanRegistrator() {
    return new SpringBeanRegistrator(this.applicationContext);
  }

  /**
   * Creates the {@link SignServiceEngineManager} bean.
   *
   * @param signServiceFactory the factory for creating a manager bean
   * @return a SignServiceEngineManager bean
   * @throws Exception for configuration errors
   */
  @ConditionalOnMissingBean
  @Bean("signservice.SignServiceEngineManager")
  public SignServiceEngineManager signServiceEngineManager(
      final SignServiceFactory signServiceFactory) throws Exception {

    return signServiceFactory.createSignServiceEngineManager(this.properties, this.beanLoader(),
        this.beanRegistrator());
  }

}
