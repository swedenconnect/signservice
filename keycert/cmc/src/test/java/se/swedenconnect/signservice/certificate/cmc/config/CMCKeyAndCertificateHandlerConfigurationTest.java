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
package se.swedenconnect.signservice.certificate.cmc.config;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.core.config.PkiCredentialConfiguration;
import se.swedenconnect.signservice.core.config.PkiCredentialConfigurationProperties;

/**
 * Test cases for CMCKeyAndCertificateHandlerConfiguration.
 */
public class CMCKeyAndCertificateHandlerConfigurationTest {

  @Test
  public void testFactory() {
    final CMCKeyAndCertificateHandlerConfiguration config = new CMCKeyAndCertificateHandlerConfiguration();
    Assertions.assertEquals(CMCKeyAndCertificateHandlerFactory.class.getName(), config.getFactoryClass());
  }

  @Test
  public void testCred() {
    final CMCKeyAndCertificateHandlerConfiguration config = new CMCKeyAndCertificateHandlerConfiguration();

    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setResource("classpath:cmc-client.jks");
    props.setPassword("secret".toCharArray());
    props.setAlias("cmc");
    props.setKeyPassword("secret".toCharArray());

    config.setCmcClientCredential(new PkiCredentialConfiguration(props));

    final PkiCredential cred = config.getCmcClientCredential().resolvePkiCredential(null);
    Assertions.assertNotNull(cred);
  }

  @Test
  public void testCredThrows() {
    final CMCKeyAndCertificateHandlerConfiguration config = new CMCKeyAndCertificateHandlerConfiguration();

    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setPassword("secret".toCharArray());
    props.setAlias("cmc");
    props.setKeyPassword("secret".toCharArray());

    config.setCmcClientCredential(new PkiCredentialConfiguration(props));

    Assertions.assertThrows(Exception.class, () -> config.getCmcClientCredential().resolvePkiCredential(null));
  }

  @Test
  public void testNull() {
    final CMCKeyAndCertificateHandlerConfiguration config = new CMCKeyAndCertificateHandlerConfiguration();
    Assertions.assertNull(config.getCmcClientCredential());
  }

}
