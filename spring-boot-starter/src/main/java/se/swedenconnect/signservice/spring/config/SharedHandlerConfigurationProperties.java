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
package se.swedenconnect.signservice.spring.config;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.signservice.spring.config.authn.AuthenticationConfigurationProperties;
import se.swedenconnect.signservice.spring.config.protocol.ProtocolConfigurationProperties;

/**
 * Shared, or default, configuration properties that may be merged into the engine configuration.
 */
public class SharedHandlerConfigurationProperties {

  /**
   * Default/shared protocol handler configuration.
   */
  @Getter
  @Setter
  private ProtocolConfigurationProperties protocol;

  /**
   * Default/shared authentication handler configuration.
   */
  @Getter
  @Setter
  private AuthenticationConfigurationProperties authn;

}