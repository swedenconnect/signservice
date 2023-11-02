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

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import se.swedenconnect.security.credential.container.InMemoryPkiCredentialContainer;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;

/**
 * Test cases for CredentialContainerConfiguration.
 */
public class CredentialContainerConfigurationTest {

  @BeforeAll
  static void init() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
  }

  @Test
  public void testInMemory() {
    final CredentialContainerConfiguration conf = CredentialContainerConfiguration.builder()
        .securityProvider("BC")
        .build();
    final PkiCredentialContainer container = conf.create();
    Assertions.assertTrue(InMemoryPkiCredentialContainer.class.isInstance(container));
  }

  @Test
  public void testInMemoryDefault() {
    final CredentialContainerConfiguration conf = CredentialContainerConfiguration.builder()
        .build();
    final PkiCredentialContainer container = conf.create();
    Assertions.assertTrue(InMemoryPkiCredentialContainer.class.isInstance(container));
  }

  @Test
  public void testHsmFailLoad() {
    final CredentialContainerConfiguration conf = CredentialContainerConfiguration.builder()
        .hsmConfigurationFile("/not/a/valid/path")
        .hsmPin("1111")
        .build();
    assertThatThrownBy(() -> {
      conf.create();
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Invalid HSM credential container configuration for user key generation");
  }

  @Test
  public void testHsmMissingPin() {
    final CredentialContainerConfiguration conf = CredentialContainerConfiguration.builder()
        .hsmConfigurationFile("/not/a/valid/path")
        .build();
    assertThatThrownBy(() -> {
      conf.create();
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("HSM PIN must be assigned");
  }

}
