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
package se.swedenconnect.signservice.spring.config.authn;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.authn.mock.MockedAuthenticationHandlerConfiguration;
import se.swedenconnect.signservice.core.config.BeanReferenceHandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;
import se.swedenconnect.signservice.spring.config.HandlerConfigurationProperties;

/**
 * Properties for authentication configuration.
 */
public class AuthenticationConfigurationProperties implements HandlerConfigurationProperties<AuthenticationHandler> {

  /**
   * Configuration for using a mocked authentication handler.
   */
  @Getter
  @Setter
  private MockedAuthenticationHandlerConfiguration mock;

  /**
   * Configuration that points to an already configured authentication handler bean.
   */
  private BeanReferenceHandlerConfiguration<AuthenticationHandler> external;

  /** {@inheritDoc} */
  @Override
  @Nullable
  public BeanReferenceHandlerConfiguration<AuthenticationHandler> getExternal() {
    return this.external;
  }

  /** {@inheritDoc} */
  @Override
  public void setExternal(@Nullable final BeanReferenceHandlerConfiguration<AuthenticationHandler> external) {
    this.external = external;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public HandlerConfiguration<AuthenticationHandler> getHandlerConfiguration() throws IllegalArgumentException {
    if (this.external != null && (this.mock != null && this.mock.isActive())) {
      throw new IllegalArgumentException("Both mock and external configuration supplied, only one can be assigned");
    }
    if (this.external == null && (this.mock == null || (this.mock != null && !this.mock.isActive()))) {
      throw new IllegalArgumentException("Missing configuration");
    }
    if (this.external != null) {
      return this.external;
    }
    else { // mock
      return this.mock;
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public HandlerConfiguration<AuthenticationHandler> getHandlerConfiguration(@Nonnull final String name) {
    if ("mock".equalsIgnoreCase(name)) {
      return this.mock != null ? (this.mock.isActive() ? this.mock : null) : null;
    }
    else if ("external".equalsIgnoreCase(name)) {
      return this.external;
    }
    else {
      return null;
    }
  }

}
