/*
 * Copyright 2022-2023 Sweden Connect
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
package se.swedenconnect.signservice.certificate.base.config;

import java.security.KeyStoreException;

import org.apache.commons.lang3.StringUtils;

import jakarta.annotation.Nonnull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.container.HsmPkiCredentialContainer;
import se.swedenconnect.security.credential.container.InMemoryPkiCredentialContainer;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;

/**
 * Configuration for creating a {@link PkiCredentialContainer}.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Slf4j
public class CredentialContainerConfiguration {

  /**
   * A full path to the PKCS#11 configuration file. If not provided generation and use of software based keys will be
   * effective.
   */
  private String hsmConfigurationFile;

  /**
   * The PIN/password used to access the HSM slot if HSM is used.
   */
  private String hsmPin;

  /**
   * The name of the crypto provider used to generate software based keys. This value is ignored if the
   * hsmConfigurationFile property is set. If not provided, a default security provider will be used.
   */
  private String securityProvider;

  /**
   * Based on the configuration object a {@link PkiCredentialContainer} is created.
   * @return a PkiCredentialContainer
   * @throws IllegalArgumentException for configuration errors
   */
  @Nonnull
  public PkiCredentialContainer create() throws IllegalArgumentException {
    if (StringUtils.isNotBlank(this.hsmConfigurationFile)) {
      if (StringUtils.isBlank(this.hsmPin)) {
        throw new IllegalArgumentException("HSM PIN must be assigned");
      }
      try {
        return new HsmPkiCredentialContainer(this.hsmConfigurationFile, this.hsmPin);
      }
      catch (final KeyStoreException e) {
        throw new IllegalArgumentException("Invalid HSM credential container configuration for user key generation",
            e);
      }
    }
    else {
      String securityProvider = this.securityProvider;
      if (StringUtils.isBlank(securityProvider)) {
        securityProvider = "BC";
        log.info("No security provider supplied, using {}", securityProvider);
      }
      return new InMemoryPkiCredentialContainer(securityProvider);
    }
  }

}
