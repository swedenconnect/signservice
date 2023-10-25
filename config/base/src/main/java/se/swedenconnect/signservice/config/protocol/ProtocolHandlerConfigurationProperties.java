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
package se.swedenconnect.signservice.config.protocol;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.signservice.config.HandlerConfigurationProperties;
import se.swedenconnect.signservice.core.config.BeanReferenceHandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;
import se.swedenconnect.signservice.protocol.ProtocolHandler;
import se.swedenconnect.signservice.protocol.dss.DssProtocolHandlerConfiguration;

/**
 * Properties for protocol configuration.
 */
public class ProtocolHandlerConfigurationProperties implements HandlerConfigurationProperties<ProtocolHandler> {

  /**
   * Configuration for the DSS protocol.
   */
  @Getter
  @Setter
  private DssProtocolHandlerConfiguration dss;

  /**
   * Configuration that points to an already configured protocol handler bean.
   */
  private BeanReferenceHandlerConfiguration<ProtocolHandler> external;

  /** {@inheritDoc} */
  @Override
  @Nullable
  public BeanReferenceHandlerConfiguration<ProtocolHandler> getExternal() {
    return this.external;
  }

  /** {@inheritDoc} */
  @Override
  public void setExternal(@Nullable final BeanReferenceHandlerConfiguration<ProtocolHandler> external) {
    this.external = external;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public HandlerConfiguration<ProtocolHandler> getHandlerConfiguration() throws IllegalArgumentException {
    if (this.external != null && this.dss != null) {
      throw new IllegalArgumentException("Both dss and external configuration supplied, only one can be assigned");
    }
    if (this.external == null && this.dss == null) {
      throw new IllegalArgumentException("Missing configuration");
    }
    return this.dss != null ? this.dss : this.external;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public HandlerConfiguration<ProtocolHandler> getHandlerConfiguration(@Nonnull final String name) {

    if ("dss".equalsIgnoreCase(name)) {
      return this.dss;
    }
    else if ("external".equalsIgnoreCase(name)) {
      return this.external;
    }
    else {
      return null;
    }
  }

}
