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
package se.swedenconnect.signservice.authn.saml.config;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.factory.PkiCredentialFactoryBean;

/**
 * An extension of {@link SamlAuthenticationHandlerConfiguration} so that it can be used as a Spring Boot configuration
 * properties class.
 */
public class SpringSamlAuthenticationHandlerConfiguration extends SamlAuthenticationHandlerConfiguration {

  /**
   * SAML SP default credential from a properties object. Used if no specific credential is given for signing and/or
   * encrypt/decrypt.
   */
  @Getter
  @Setter
  private PkiCredentialConfigurationProperties defaultCredentialProps;

  // Internal
  private PkiCredentialFactoryBean defaultCredentialFactory;
  private int defaultCredentialPropsHash;

  /**
   * The SAML SP signature credential.
   */
  @Getter
  @Setter
  private PkiCredentialConfigurationProperties signatureCredentialProps;

  // Internal
  private PkiCredentialFactoryBean signatureCredentialFactory;
  private int signatureCredentialPropsHash;

  /**
   * The SAML SP decryption credential.
   */
  @Getter
  @Setter
  private PkiCredentialConfigurationProperties decryptionCredentialProps;

  // Internal
  private PkiCredentialFactoryBean decryptionCredentialFactory;
  private int decryptionCredentialPropsHash;

  /** {@inheritDoc} */
  @Override
  @Nullable
  public PkiCredential getDefaultCredential() {
    if (this.defaultCredentialProps != null) {
      if (this.defaultCredentialFactory == null
          || this.defaultCredentialPropsHash != this.defaultCredentialProps.hashCode()) {
        this.defaultCredentialFactory = this.initCredentialFactory(this.defaultCredentialProps);
        this.defaultCredentialPropsHash = this.defaultCredentialProps.hashCode();
      }
      try {
        return this.defaultCredentialFactory.getObject();
      }
      catch (final Exception e) {
        throw new IllegalArgumentException("Failed to initialize default credential - " + e.getMessage(), e);
      }
    }
    return super.getDefaultCredential();
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public PkiCredential getSignatureCredential() {
    if (this.signatureCredentialProps != null) {
      if (this.signatureCredentialFactory == null
          || this.signatureCredentialPropsHash != this.signatureCredentialProps.hashCode()) {
        this.signatureCredentialFactory = this.initCredentialFactory(this.signatureCredentialProps);
        this.signatureCredentialPropsHash = this.signatureCredentialProps.hashCode();
      }
      try {
        return this.signatureCredentialFactory.getObject();
      }
      catch (final Exception e) {
        throw new IllegalArgumentException("Failed to initialize signature credential - " + e.getMessage(), e);
      }
    }
    return super.getSignatureCredential();
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public PkiCredential getDecryptionCredential() {
    if (this.decryptionCredentialProps != null) {
      if (this.decryptionCredentialFactory == null
          || this.decryptionCredentialPropsHash != this.decryptionCredentialProps.hashCode()) {
        this.decryptionCredentialFactory = this.initCredentialFactory(this.decryptionCredentialProps);
        this.decryptionCredentialPropsHash = this.decryptionCredentialProps.hashCode();
      }
      try {
        return this.decryptionCredentialFactory.getObject();
      }
      catch (final Exception e) {
        throw new IllegalArgumentException("Failed to initialize decryption credential - " + e.getMessage(), e);
      }
    }
    return super.getDecryptionCredential();
  }

  /**
   * Helper method to create a {@link PkiCredentialFactoryBean} given a properties object.
   *
   * @param props the properties
   * @return a credential factory
   */
  private PkiCredentialFactoryBean initCredentialFactory(
      @Nonnull final PkiCredentialConfigurationProperties props) {
    final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean(props);
    factory.setSingleton(true);
    try {
      factory.afterPropertiesSet();
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to initialize credential - " + e.getMessage(), e);
    }
    return factory;
  }

}
