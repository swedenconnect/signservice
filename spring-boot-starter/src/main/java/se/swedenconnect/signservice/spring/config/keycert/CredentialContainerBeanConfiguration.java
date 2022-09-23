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

import org.springframework.util.Assert;

import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.config.CredentialContainerConfiguration;
import se.swedenconnect.signservice.spring.config.CommonBeanCandidate;

/**
 * A {@link KeyAndCertificateHandler} needs a {@link PkiCredentialContainer} that it uses for key generation (user
 * signing credentials). There is an advantage to use only <b>one</b> such instance, for example for easy scheduling of
 * the {@link PkiCredentialContainer#cleanup()} method. This class configures such a bean.
 */
public class CredentialContainerBeanConfiguration extends CredentialContainerConfiguration
    implements CommonBeanCandidate {

  /**
   * The bean name for the key provider bean.
   */
  private String beanName;

  @Override
  @Nonnull
  public String getBeanName() {
    return this.beanName;
  }

  @Override
  public void setBeanName(@Nonnull final String beanName) {
    this.beanName = beanName;
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.hasText(this.beanName, "Missing bean-name for SAML metadata provider bean configuration");
  }

}
