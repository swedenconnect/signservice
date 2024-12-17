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
package se.swedenconnect.signservice.config.sign;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.signservice.config.HandlerConfigurationProperties;
import se.swedenconnect.signservice.core.config.BeanReferenceHandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;
import se.swedenconnect.signservice.signature.SignatureHandler;
import se.swedenconnect.signservice.signature.config.DefaultSignatureHandlerConfiguration;

/**
 * Configuration properties for signature handlers.
 */
public class SignatureHandlerConfigurationProperties implements HandlerConfigurationProperties<SignatureHandler> {

  /**
   * Configuration that points to an already configured signature handler bean.
   */
  private BeanReferenceHandlerConfiguration<SignatureHandler> external;

  /**
   * Configuration for using the default sign handler.
   */
  @Getter
  @Setter
  private DefaultSignatureHandlerConfiguration defaultHandler;

  /** {@inheritDoc} */
  @Override
  @Nullable
  public BeanReferenceHandlerConfiguration<SignatureHandler> getExternal() {
    return this.external;
  }

  /** {@inheritDoc} */
  @Override
  public void setExternal(@Nullable final BeanReferenceHandlerConfiguration<SignatureHandler> external) {
    this.external = external;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public HandlerConfiguration<SignatureHandler> getHandlerConfiguration() throws IllegalArgumentException {
    if (this.external == null && this.defaultHandler == null) {
      throw new IllegalArgumentException("Missing configuration");
    }
    else if (this.external != null && this.defaultHandler != null) {
      throw new IllegalArgumentException("Both external and default-handler are set, not allowed");
    }
    else if (this.defaultHandler != null) {
      return this.defaultHandler;
    }
    else {
      return this.external;
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public HandlerConfiguration<SignatureHandler> getHandlerConfiguration(@Nonnull final String name) {
    if ("default-handler".equalsIgnoreCase(name) || "defaultHandler".equalsIgnoreCase(name) ||
        "DEFAULT_HANDLER".equalsIgnoreCase(name)) {
      return this.defaultHandler;
    }
    else if ("external".equalsIgnoreCase(name)) {
      return this.external;
    }
    else {
      return null;
    }
  }

}
