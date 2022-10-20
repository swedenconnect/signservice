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
package se.swedenconnect.signservice.config.protocol;

import javax.annotation.Nonnull;
import javax.annotation.PostConstruct;

import org.springframework.util.Assert;

import se.swedenconnect.signservice.config.common.CommonBeanCandidate;

/**
 * Configuration for a common protocol handler bean.
 */
public class ProtocolHandlerBeanConfigurationProperties extends ProtocolHandlerConfigurationProperties
    implements CommonBeanCandidate {

  /**
   * The bean name for the protocol handler bean.
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
    Assert.hasText(this.beanName, "Missing bean-name for protocol handler bean configuration");
  }

}
