/*
 * Copyright 2022-2025 Sweden Connect
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
    if (this.props != null) {
      try {
        this.props.afterPropertiesSet();
        return PkiCredentialFactorySingleton.getInstance().getPkiCredentialFactory().createCredential(this.props);
      }
      catch (final Exception e) {
        throw new IllegalArgumentException("Failed to initialize credential - " + e.getMessage(), e);
      }
    }
    return this.cred;
  }

}
