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

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.factory.PkiCredentialFactoryBean;

/**
 * Test cases for PkiCredentialConfiguration.
 */
public class PkiCredentialConfigurationTest {

  @Test
  public void testNull() {
    final PkiCredentialConfiguration config = new PkiCredentialConfiguration();
    Assertions.assertNull(config.getBeanReference());
    Assertions.assertNull(config.getCred());
    Assertions.assertNull(config.getProps());
    Assertions.assertNull(config.resolvePkiCredential(null));
  }

  @Test
  public void testBean() throws Exception {
    final PkiCredential credential = this.getCredential("CRED");
    final BeanLoader beanLoader = new BeanLoader() {

      @Override
      public <T> T load(final String beanName, final Class<T> type) {
        return type.cast(credential);
      }
    };

    final PkiCredentialConfiguration config = new PkiCredentialConfiguration("our.bean.name");

    Assertions.assertEquals("our.bean.name", config.getBeanReference());
    Assertions.assertNull(config.getCred());
    Assertions.assertNull(config.getProps());

    assertThatThrownBy(() -> {
      config.resolvePkiCredential(null);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Can not resolve credential - beanReference is set and no bean loader provided");

    final PkiCredential resolved = config.resolvePkiCredential(beanLoader);
    Assertions.assertEquals(credential.getName(), resolved.getName());
  }

  @Test
  public void testProps() {
    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setResource(new ClassPathResource("keys.jks"));
    props.setAlias("sign");
    props.setPassword("secret".toCharArray());
    props.setName("PROP");
    final PkiCredentialConfiguration config = new PkiCredentialConfiguration(props);

    final PkiCredential cred = config.resolvePkiCredential(null);
    Assertions.assertNotNull(cred);
    Assertions.assertEquals("PROP", cred.getName());

    // Assert that the same object is returned next time
    Assertions.assertTrue(cred == config.resolvePkiCredential(null));

    // Make a change to the config object and assert that a new object is returned.
    config.getProps().setName("PROP2");
    final PkiCredential cred2 = config.resolvePkiCredential(null);
    Assertions.assertNotNull(cred2);
    Assertions.assertEquals("PROP2", cred2.getName());
    Assertions.assertFalse(cred == cred2);
  }

  @Test
  public void testPropsError() {
    final PkiCredentialConfigurationProperties props = new PkiCredentialConfigurationProperties();
    props.setResource(new ClassPathResource("keys.jks"));
    props.setAlias("sign");
    props.setName("PROP");
    final PkiCredentialConfiguration config = new PkiCredentialConfiguration(props);
    assertThatThrownBy(() -> {
      config.resolvePkiCredential(null);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Failed to initialize credential - ");
  }

  @Test
  public void testCred() throws Exception {
    final PkiCredential cred = this.getCredential("CRED");
    final PkiCredentialConfiguration config = new PkiCredentialConfiguration(cred);
    Assertions.assertNull(config.getBeanReference());
    Assertions.assertNull(config.getProps());
    final PkiCredential cred2 = config.getCred();
    Assertions.assertTrue(cred == cred2);
    final PkiCredential resolved = config.resolvePkiCredential(null);
    Assertions.assertTrue(cred == resolved);
  }

  private PkiCredential getCredential(final String name) throws Exception {
    final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean();
    factory.setResource(new ClassPathResource("keys.jks"));
    factory.setAlias("sign");
    factory.setPassword("secret".toCharArray());
    factory.setName(name);
    factory.afterPropertiesSet();
    return factory.getObject();
  }

}
