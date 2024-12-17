/*
 * Copyright 2022-2024 Sweden Connect
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
import se.swedenconnect.signservice.config.common.CommonBeanCandidate;

/**
 * Properties for a common authentication handler bean.
 */
public class AuthenticationHandlerBeanConfigurationProperties extends AuthenticationHandlerConfigurationProperties implements
    CommonBeanCandidate {

  /**
   * The bean name for the authentication handler bean.
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

  @Override
  @PostConstruct
  public void afterPropertiesSet() throws IllegalArgumentException {
    if (StringUtils.isBlank(this.beanName)) {
      throw new IllegalArgumentException("Missing bean-name for authentication handler bean configuration");
    }
  }

}
