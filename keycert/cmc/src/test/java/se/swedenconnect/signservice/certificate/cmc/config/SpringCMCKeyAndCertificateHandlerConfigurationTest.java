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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;

/**
 * Test cases for SpringCMCKeyAndCertificateHandlerConfiguration.
 */
public class SpringCMCKeyAndCertificateHandlerConfigurationTest {

  @Test
  public void testCred() {
    SpringCMCKeyAndCertificateHandlerConfiguration config = new SpringCMCKeyAndCertificateHandlerConfiguration();

    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setResource(new ClassPathResource("cmc-client.jks"));
    props.setPassword("secret".toCharArray());
    props.setAlias("cmc");
    props.setKeyPassword("secret".toCharArray());

    config.setClientCredentialProps(props);

    final PkiCredential cred = config.getClientCredential();

    Assertions.assertNotNull(cred);

    // Assert that the same object is returned
    Assertions.assertEquals(cred, config.getClientCredential());
  }

  @Test
  public void testCredThrows() {
    SpringCMCKeyAndCertificateHandlerConfiguration config = new SpringCMCKeyAndCertificateHandlerConfiguration();

    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setPassword("secret".toCharArray());
    props.setAlias("cmc");
    props.setKeyPassword("secret".toCharArray());

    config.setClientCredentialProps(props);

    Assertions.assertThrows(Exception.class, () -> config.getClientCredential());
  }

  @Test
  public void testNull() {
    SpringCMCKeyAndCertificateHandlerConfiguration config = new SpringCMCKeyAndCertificateHandlerConfiguration();
    Assertions.assertNull(config.getClientCredential());
  }

}
