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
package se.swedenconnect.signservice.config.common;

import javax.annotation.PostConstruct;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.signservice.config.authn.SamlMetadataProviderBeanConfiguration;
import se.swedenconnect.signservice.config.cert.KeyAndCertificateHandlerBeanConfigurationProperties;
import se.swedenconnect.signservice.config.protocol.ProtocolHandlerBeanConfigurationProperties;
import se.swedenconnect.signservice.config.sign.SignatureHandlerBeanConfigurationProperties;

/**
 * The configuration for some handlers, and also some other beans, normally do not differ between different engines
 * (clients). It is not very efficient if every engine instance instantiates their own beans (for handlers or other base
 * components). Instead the engine configuration can point to an already existing bean. This configuration properties
 * class defines the configuration for components that may be "common".
 */
public class CommonBeansConfigurationProperties {

  /**
   * Protocol handler configuration for a common protocol handler bean.
   */
  @Getter
  @Setter
  private ProtocolHandlerBeanConfigurationProperties protocol;

  /**
   * Signature handler configuration for a common signature handler bean.
   */
  @Getter
  @Setter
  private SignatureHandlerBeanConfigurationProperties sign;

  /**
   * A key provider ({@link PkiCredentialContainer}) that may be referenced in the configuration for a key and
   * certificate handler.
   */
  @Getter
  @Setter
  private CredentialContainerBeanConfiguration keyProvider;

  /**
   * Key and certificate handler configuration for a common bean.
   */
  @Getter
  @Setter
  private KeyAndCertificateHandlerBeanConfigurationProperties cert;

  /**
   * SAML bean configuration data.
   */
  @Getter
  @Setter
  private Saml saml;

  /**
   * Asserts that all settings have been applied.
   *
   * @throws IllegalArgumentException for config errors
   */
  @PostConstruct
  public void afterPropertiesSet() throws IllegalArgumentException {
    if (this.protocol != null) {
      this.protocol.afterPropertiesSet();
    }
    if (this.sign != null) {
      this.sign.afterPropertiesSet();
    }
    if (this.cert != null) {
      this.cert.afterPropertiesSet();
    }
    if (this.saml != null) {
      this.saml.afterPropertiesSet();
    }
  }

  /**
   * SAML bean configuration data.
   */
  @Data
  public static class Saml {

    /**
     * A signature service normally has the same metadata provider for all of its clients, and a provider instance is
     * pretty expensive to create, or rather, it spawns threads that download SAML metadata periodically. Having X
     * clients doing the same task is completely unnecessary. Therefore it is possible to create a stand-alone
     * {@link MetadataProvider} bean that is referenced by all the client SAML handlers.
     */
    private SamlMetadataProviderBeanConfiguration metadataProvider;

    /**
     * Asserts that all settings have been applied.
     *
     * @throws IllegalArgumentException for config errors
     */
    @PostConstruct
    public void afterPropertiesSet() throws IllegalArgumentException {
      if (this.metadataProvider != null) {
        this.metadataProvider.afterPropertiesSet();
      }
    }
  }

}
