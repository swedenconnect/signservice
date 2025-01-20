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
package se.swedenconnect.signservice.config.authn;

import org.apache.commons.lang3.StringUtils;

import jakarta.annotation.Nonnull;
import jakarta.annotation.PostConstruct;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.signservice.authn.saml.config.MetadataProviderConfiguration;
import se.swedenconnect.signservice.config.common.CommonBeanCandidate;

/**
 * A signature service normally has the same metadata provider for all of its clients, and a provider instance is pretty
 * expensive to create, or rather, it spawns threads that download SAML metadata periodically. Having X clients doing
 * the same task is completely unnecessary. Therefore it is possible to create a stand-alone
 * {@link MetadataProvider} bean that is referenced by all the client SAML handlers.
 */
public class SamlMetadataProviderBeanConfiguration extends MetadataProviderConfiguration
    implements CommonBeanCandidate {

  /**
   * The bean name for the SAML metadata provider bean.
   */
  private String beanName;

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getBeanName() {
    return this.beanName;
  }

  /** {@inheritDoc} */
  @Override
  public void setBeanName(@Nonnull final String beanName) {
    this.beanName = beanName;
  }

  /** {@inheritDoc} */
  @Override
  @PostConstruct
  public void afterPropertiesSet() throws IllegalArgumentException {
    if (StringUtils.isBlank(this.beanName)) {
      throw new IllegalArgumentException("Missing bean-name for SAML metadata provider bean configuration");
    }
  }

}
