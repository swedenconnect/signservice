/*
 * Copyright 2022-2023 Sweden Connect
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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.authn.mock.MockedAuthenticationHandlerConfiguration;
import se.swedenconnect.signservice.authn.saml.config.SamlAuthenticationHandlerConfiguration;
import se.swedenconnect.signservice.config.HandlerConfigurationProperties;
import se.swedenconnect.signservice.core.config.BeanReferenceHandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Properties for authentication configuration.
 */
public class AuthenticationHandlerConfigurationProperties
    implements HandlerConfigurationProperties<AuthenticationHandler> {

  /**
   * Configuration for using a mocked authentication handler.
   */
  @Getter
  @Setter
  private MockedAuthenticationHandlerConfiguration mock;

  /**
   * Configuration for using the SAML authentication handler.
   */
  @Getter
  @Setter
  private SamlAuthenticationHandlerConfiguration saml;

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
    final int noAssigned = (this.saml != null ? 1 : 0) + (this.mock != null && this.mock.isActive() ? 1 : 0)
        + (this.external != null ? 1 : 0);
    if (noAssigned > 1) {
      throw new IllegalArgumentException(
          "Several authentication handler configurations supplied, only one can be assigned");
    }
    else if (noAssigned == 0) {
      throw new IllegalArgumentException("Missing configuration");
    }

    return this.saml != null ? this.saml : this.external != null ? this.external : this.mock;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public HandlerConfiguration<AuthenticationHandler> getHandlerConfiguration(@Nonnull final String name) {
    if ("saml".equalsIgnoreCase(name)) {
      return this.saml;
    }
    else if ("mock".equalsIgnoreCase(name)) {
      return this.mock;
    }
    else if ("external".equalsIgnoreCase(name)) {
      return this.external;
    }
    else {
      return null;
    }
  }

}
