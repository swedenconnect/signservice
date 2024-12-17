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
package se.swedenconnect.signservice.core.config;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.factory.PkiCredentialFactoryBean;

import java.util.Arrays;
import java.util.Objects;

/**
 * A configuration object for configuring {@link PkiCredential} objects.
 */
public class PkiCredentialConfiguration {

  /**
   * A reference to a {@link PkiCredential} bean.
   */
  @Getter
  @Setter
  private String beanReference;

  /**
   * The credential instance.
   */
  @Getter
  @Setter
  private PkiCredential cred;

  /**
   * A configuration properties object for creating a {@link PkiCredential}.
   */
  @Getter
  @Setter
  private PkiCredentialConfigurationProperties props;

  // Internal
  private final Resolver resolver = new Resolver();

  /**
   * Default constructor.
   */
  public PkiCredentialConfiguration() {
  }

  /**
   * Constructor setting up the configuration object with a bean reference.
   *
   * @param beanReference the bean name of the PkiCredential bean to load
   */
  public PkiCredentialConfiguration(@Nonnull final String beanReference) {
    this.beanReference = Objects.requireNonNull(beanReference, "beanReference must not be null");
  }

  /**
   * Constructor setting up the configuration object with a {@link PkiCredential} instance.
   *
   * @param cred the PkiCredential instance
   */
  public PkiCredentialConfiguration(@Nonnull final PkiCredential cred) {
    this.cred = Objects.requireNonNull(cred, "cred must not be null");
  }

  /**
   * Constructor setting up the configuration object with a {@link PkiCredentialConfigurationProperties} object that is
   * used to create the credential.
   *
   * @param props configuration properties object
   */
  public PkiCredentialConfiguration(@Nonnull final PkiCredentialConfigurationProperties props) {
    this.props = Objects.requireNonNull(props, "props must not be null");
  }

  /**
   * Given an instantiated configuration object this method resolves it into a {@link PkiCredential} object.
   *
   * @param beanLoader the bean loader. If null, resolving of bean references will not be possible
   * @return a PkiCredential object, or null if none has been assigned
   * @throws IllegalArgumentException for configuration errors
   */
  @Nullable
  public PkiCredential resolvePkiCredential(@Nullable final BeanLoader beanLoader) throws IllegalArgumentException {
    if (StringUtils.isNotBlank(this.beanReference)) {
      if (beanLoader == null) {
        throw new IllegalArgumentException(
            "Can not resolve credential - beanReference is set and no bean loader provided");
      }
      return beanLoader.load(this.beanReference, PkiCredential.class);
    }
    return this.resolver.getCredential();
  }

  /**
   * Helper class for resolving a {@link PkiCredential} given a {@link PkiCredentialConfigurationProperties} object. The
   * logic handles changes made to the configuration properties object during the lifetime of the configuration object.
   */
  private class Resolver {

    /** The factory used to create {@link PkiCredential} objects. */
    private PkiCredentialFactoryBean credentialFactory;

    /** The hash of the credentials property object. */
    private int credentialPropsHash;

    /**
     * Gets the credential property by first checking the PkiCredentialConfigurationProperties and if that is set, load
     * a credential, and otherwise use the PkiCredential property.
     *
     * @return the credential or null
     */
    @Nullable
    public PkiCredential getCredential() {
      if (PkiCredentialConfiguration.this.props != null) {
        try {
          if (this.credentialFactory == null
              || this.credentialPropsHash != this.calculateHash()) {
            this.credentialFactory = new PkiCredentialFactoryBean(PkiCredentialConfiguration.this.props);
            this.credentialFactory.setSingleton(true);
            this.credentialFactory.afterPropertiesSet();
            this.credentialPropsHash = this.calculateHash();
          }
          return this.credentialFactory.getObject();
        }
        catch (final Exception e) {
          throw new IllegalArgumentException("Failed to initialize credential - " + e.getMessage(), e);
        }
      }
      return PkiCredentialConfiguration.this.cred;
    }

    private int calculateHash() {
      final PkiCredentialConfigurationProperties p = PkiCredentialConfiguration.this.props;
      return Objects.hash(p.getAlias(), p.getName(), Arrays.hashCode(p.getKeyPassword()),
          Arrays.hashCode(p.getPassword()), p.getCertificate(), p.getPkcs11Configuration(),
          p.getProvider(), p.getType(), p.getPrivateKey());
    }
  }

}
