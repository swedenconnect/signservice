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
package se.swedenconnect.signservice.certificate.simple.config;

import javax.annotation.Nullable;

import lombok.Getter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.factory.PkiCredentialFactoryBean;

/**
 * Configuration class for {@link SimpleKeyAndCertificateHandlerConfiguration} to be used in Spring Boot environments.
 */
public class SpringSimpleKeyAndCertificateHandlerConfiguration extends SimpleKeyAndCertificateHandlerConfiguration {

  /**
   * The CMC client credential properties.
   */
  @Getter
  private PkiCredentialConfigurationProperties caCredentialProps;

  // Internal
  private PkiCredentialFactoryBean caCredentialFactory;
  private int caCredentialPropsHash;

  /** {@inheritDoc} */
  @Override
  @Nullable
  public PkiCredential getCaCredential() {
    if (this.caCredentialProps != null) {
      try {
        if (this.caCredentialFactory == null || this.caCredentialPropsHash != this.caCredentialProps.hashCode()) {
          this.caCredentialFactory = new PkiCredentialFactoryBean(this.caCredentialProps);
          this.caCredentialFactory.setSingleton(true);
          this.caCredentialFactory.afterPropertiesSet();
          this.caCredentialPropsHash = this.caCredentialProps.hashCode();
        }
        return this.caCredentialFactory.getObject();
      }
      catch (final Exception e) {
        throw new IllegalArgumentException("Failed to initialize CA credential - " + e.getMessage(), e);
      }
    }
    return super.getCaCredential();
  }

  /**
   * The CA credential properties.
   *
   * @param caCredentialProps the properties
   */
  public void setCaCredentialProps(@Nullable final PkiCredentialConfigurationProperties caCredentialProps) {
    this.caCredentialProps = caCredentialProps;
    this.caCredentialFactory = null;
  }

}
