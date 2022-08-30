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

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;

/**
 * Test cases for SpringSamlAuthenticationHandlerConfiguration.
 */
public class SpringSamlAuthenticationHandlerConfigurationTest {

  @Test
  public void testGetters() {
    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setResource(new ClassPathResource("keys.jks"));
    props.setName("CRED");
    props.setAlias("sign");
    props.setPassword("secret".toCharArray());
    props.setKeyPassword("secret".toCharArray());

    final SpringSamlAuthenticationHandlerConfiguration conf = new SpringSamlAuthenticationHandlerConfiguration();

    Assertions.assertNull(conf.getDefaultCredential());
    Assertions.assertNull(conf.getSignatureCredential());
    Assertions.assertNull(conf.getDecryptionCredential());

    conf.setDefaultCredentialProps(props);
    conf.setSignatureCredentialProps(props);
    conf.setDecryptionCredentialProps(props);

    final PkiCredential cred = conf.getDefaultCredential();
    Assertions.assertEquals("CRED", cred.getName());
    // Assert that the same object is returned next time
    Assertions.assertTrue(cred == conf.getDefaultCredential());

    final PkiCredential cred2 = conf.getSignatureCredential();
    Assertions.assertEquals("CRED", cred2.getName());
    Assertions.assertTrue(cred2 == conf.getSignatureCredential());

    final PkiCredential cred3 = conf.getDecryptionCredential();
    Assertions.assertEquals("CRED", cred3.getName());
    Assertions.assertTrue(cred3 == conf.getDecryptionCredential());

    // Assert that a new object is returned ...
    conf.getDefaultCredentialProps().setAlias("encrypt");
    conf.getSignatureCredentialProps().setAlias("encrypt");
    conf.getDecryptionCredentialProps().setAlias("encrypt");

    Assertions.assertFalse(cred == conf.getDefaultCredential());
    Assertions.assertFalse(cred2 == conf.getSignatureCredential());
    Assertions.assertFalse(cred3 == conf.getDecryptionCredential());
  }

  @Test
  public void testBadConfig() {
    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setAlias("sign");
    props.setPassword("secret".toCharArray());
    props.setKeyPassword("secret".toCharArray());

    final SpringSamlAuthenticationHandlerConfiguration conf = new SpringSamlAuthenticationHandlerConfiguration();

    conf.setDefaultCredentialProps(props);
    assertThatThrownBy(() -> {
      conf.getDefaultCredential();
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Failed to initialize credential - ");
  }

}
