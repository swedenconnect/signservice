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
package se.swedenconnect.signservice.certificate.simple.config;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.core.config.PkiCredentialConfiguration;
import se.swedenconnect.signservice.core.config.PkiCredentialConfigurationProperties;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test cases for SimpleKeyAndCertificateHandlerConfiguration.
 */
public class SimpleKeyAndCertificateHandlerConfigurationTest {

  @Test
  public void testFactory() {
    final SimpleKeyAndCertificateHandlerConfiguration config = new SimpleKeyAndCertificateHandlerConfiguration();
    Assertions.assertEquals(SimpleKeyAndCertificateHandlerFactory.class.getName(), config.getFactoryClass());
  }

  @Test
  public void testSetBaseUrl() {
    final SimpleKeyAndCertificateHandlerConfiguration config = new SimpleKeyAndCertificateHandlerConfiguration();

    config.setBaseUrl("https://www.example.com");

    assertThatThrownBy(() -> config.setBaseUrl("https://www.example.com/")).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("The baseUrl must not end with a '/'");

    assertThatThrownBy(() -> config.setBaseUrl(null)).isInstanceOf(NullPointerException.class)
        .hasMessage("baseUrl must not be null");
  }

  @Test
  public void testSetCrlDpPath() {
    final SimpleKeyAndCertificateHandlerConfiguration config = new SimpleKeyAndCertificateHandlerConfiguration();

    config.setCrlDpPath("/path/xyz");

    assertThatThrownBy(() -> config.setCrlDpPath("path/xyz")).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("The crlDpPath must be null or begin with a '/'");
  }

  @Test
  public void testCred() {
    final SimpleKeyAndCertificateHandlerConfiguration config = new SimpleKeyAndCertificateHandlerConfiguration();

    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setResource("classpath:test-ca.jks");
    props.setPassword("secret".toCharArray());
    props.setAlias("ec-ca");
    props.setKeyPassword("secret".toCharArray());

    config.setCaCredential(new PkiCredentialConfiguration(props));

    final PkiCredential cred = config.getCaCredential().resolvePkiCredential(null);
    Assertions.assertNotNull(cred);
  }

  @Test
  public void testCredThrows() {
    final SimpleKeyAndCertificateHandlerConfiguration config = new SimpleKeyAndCertificateHandlerConfiguration();

    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setPassword("secret".toCharArray());
    props.setAlias("rsa-ca");
    props.setKeyPassword("secret".toCharArray());

    config.setCaCredential(new PkiCredentialConfiguration(props));

    Assertions.assertThrows(Exception.class, () -> config.getCaCredential().resolvePkiCredential(null));
  }

  @Test
  public void testNull() {
    final SimpleKeyAndCertificateHandlerConfiguration config = new SimpleKeyAndCertificateHandlerConfiguration();
    Assertions.assertNull(config.getCaCredential());
  }

}
