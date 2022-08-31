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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;

/**
 * Test cases for SpringSimpleKeyAndCertificateHandlerConfiguration.
 */
public class SpringSimpleKeyAndCertificateHandlerConfigurationTest {

  @Test
  public void testCred() {
    SpringSimpleKeyAndCertificateHandlerConfiguration config = new SpringSimpleKeyAndCertificateHandlerConfiguration();

    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setResource(new ClassPathResource("test-ca.jks"));
    props.setPassword("secret".toCharArray());
    props.setAlias("ec-ca");
    props.setKeyPassword("secret".toCharArray());

    config.setCaCredentialProps(props);

    final PkiCredential cred = config.getCaCredential();
    Assertions.assertNotNull(cred);

    // Assert that the same object is returned
    Assertions.assertEquals(cred, config.getCaCredential());

    // Assert that a new object is created
    props.setAlias("rsa-ca");

    final PkiCredential cred2 = config.getCaCredential();
    Assertions.assertNotNull(cred2);
    Assertions.assertNotEquals(cred, cred2);
  }

  @Test
  public void testCredThrows() {
    SpringSimpleKeyAndCertificateHandlerConfiguration config = new SpringSimpleKeyAndCertificateHandlerConfiguration();

    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setPassword("secret".toCharArray());
    props.setAlias("rsa-ca");
    props.setKeyPassword("secret".toCharArray());

    config.setCaCredentialProps(props);

    Assertions.assertThrows(Exception.class, () -> config.getCaCredential());
  }

  @Test
  public void testNull() {
    SpringSimpleKeyAndCertificateHandlerConfiguration config = new SpringSimpleKeyAndCertificateHandlerConfiguration();
    Assertions.assertNull(config.getCaCredential());
  }

}
