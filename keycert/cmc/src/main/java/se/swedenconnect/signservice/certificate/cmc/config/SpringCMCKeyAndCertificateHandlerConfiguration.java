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
package se.swedenconnect.signservice.certificate.cmc.config;

import javax.annotation.Nullable;

import lombok.Getter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.factory.PkiCredentialFactoryBean;
import se.swedenconnect.signservice.certificate.cmc.CMCKeyAndCertificateHandler;

/**
 * Configuration class for {@link CMCKeyAndCertificateHandler} to be used in Spring Boot environments.
 */
public class SpringCMCKeyAndCertificateHandlerConfiguration extends CMCKeyAndCertificateHandlerConfiguration {

  /**
   * The CMC client credential properties.
   */
  @Getter
  private PkiCredentialConfigurationProperties clientCredentialProps;

  // Internal
  private PkiCredentialFactoryBean clientCredentialFactory;

  /** {@inheritDoc} */
  @Override
  @Nullable
  public PkiCredential getClientCredential() {
    if (this.clientCredentialProps != null) {
      try {
        if (this.clientCredentialFactory == null) {
          this.clientCredentialFactory = new PkiCredentialFactoryBean(this.clientCredentialProps);
          this.clientCredentialFactory.setSingleton(true);
          this.clientCredentialFactory.afterPropertiesSet();
        }
        return this.clientCredentialFactory.getObject();
      }
      catch (final Exception e) {
        throw new IllegalArgumentException("Failed to initialize CMC client credential - " + e.getMessage(), e);
      }
    }
    return super.getClientCredential();
  }

  /**
   * The CMC client credential properties.
   *
   * @param clientCredentialProps the properties
   */
  public void setClientCredentialProps(@Nullable final PkiCredentialConfigurationProperties clientCredentialProps) {
    this.clientCredentialProps = clientCredentialProps;
    this.clientCredentialFactory = null;
  }

}
