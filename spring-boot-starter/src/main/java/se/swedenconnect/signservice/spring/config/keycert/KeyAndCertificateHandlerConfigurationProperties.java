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
package se.swedenconnect.signservice.spring.config.keycert;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.cmc.config.SpringCMCKeyAndCertificateHandlerConfiguration;
import se.swedenconnect.signservice.certificate.simple.config.SpringSimpleKeyAndCertificateHandlerConfiguration;
import se.swedenconnect.signservice.core.config.BeanReferenceHandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;
import se.swedenconnect.signservice.spring.config.HandlerConfigurationProperties;

/**
 * Configuration properties for key and certificate handlers.
 */
public class KeyAndCertificateHandlerConfigurationProperties
    implements HandlerConfigurationProperties<KeyAndCertificateHandler> {

  /**
   * Configuration that points to an already configured key and certificate handler bean.
   */
  private BeanReferenceHandlerConfiguration<KeyAndCertificateHandler> external;

  /**
   * Configuration for a key and certificate handler that uses the CMC API to communicate with a CA.
   */
  @Setter
  @Getter
  private SpringCMCKeyAndCertificateHandlerConfiguration cmc;

  /**
   * Configuration for a built in simple CA.
   */
  @Setter
  @Getter
  private SpringSimpleKeyAndCertificateHandlerConfiguration builtInCa;

  /** {@inheritDoc} */
  @Override
  @Nullable
  public BeanReferenceHandlerConfiguration<KeyAndCertificateHandler> getExternal() {
    return this.external;
  }

  /** {@inheritDoc} */
  @Override
  public void setExternal(@Nullable final BeanReferenceHandlerConfiguration<KeyAndCertificateHandler> external) {
    this.external = external;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public HandlerConfiguration<KeyAndCertificateHandler> getHandlerConfiguration() throws IllegalArgumentException {
    final int noAssigned =
        (this.external != null ? 1 : 0) + (this.cmc != null ? 1 : 0) + (this.builtInCa != null ? 1 : 0);
    if (noAssigned > 1) {
      throw new IllegalArgumentException(
          "Several key and certificate configurations supplied, only one can be assigned");
    }
    else if (noAssigned == 0) {
      throw new IllegalArgumentException("Missing configuration");
    }
    return this.cmc != null ? this.cmc : this.builtInCa != null ? this.builtInCa : this.external;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public HandlerConfiguration<KeyAndCertificateHandler> getHandlerConfiguration(final @Nonnull String name) {
    if ("cmc".equalsIgnoreCase(name)) {
      return this.cmc;
    }
    else if ("built-in-ca".equalsIgnoreCase(name) || "buildInCa".equalsIgnoreCase(name)
        || "BUILT_IN_CA".equalsIgnoreCase(name)) {
      return this.builtInCa;
    }
    else if ("external".equalsIgnoreCase(name)) {
      return this.external;
    }
    else {
      return null;
    }
  }

}
