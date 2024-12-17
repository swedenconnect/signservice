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
package se.swedenconnect.signservice.config.spring.converters;

import java.security.cert.X509Certificate;

import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Import;

import se.swedenconnect.security.credential.converters.PropertyToX509CertificateConverter;
import se.swedenconnect.signservice.authn.saml.spring.PropertyToEntityDescriptorConverter;
import se.swedenconnect.signservice.config.spring.OpenSAMLConfiguration;

/**
 * Configuration class that registers converters for Spring converters needed to applying properties to SignService
 * configuration properties classes.
 */
@Configuration
@Import(OpenSAMLConfiguration.class)
public class SignServiceConverterConfiguration {

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
   * @return a PropertyToEntityDescriptorConverter bean
   */
  @ConditionalOnMissingBean
  @Bean
  @ConfigurationPropertiesBinding
  @DependsOn("openSAML")
  public PropertyToEntityDescriptorConverter propertyToEntityDescriptorConverter() {
    return new PropertyToEntityDescriptorConverter();
  }

  /**
   * Creates a {@link LocalizedStringConverter} bean.
   *
   * @return a LocalizedStringConverter bean
   */
  @ConditionalOnMissingBean
  @Bean
  @ConfigurationPropertiesBinding
  public LocalizedStringConverter localizedStringConverter() {
    return new LocalizedStringConverter();
  }

}
