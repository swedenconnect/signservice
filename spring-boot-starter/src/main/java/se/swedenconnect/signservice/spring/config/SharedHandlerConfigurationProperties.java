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
import se.swedenconnect.signservice.spring.config.audit.AuditLoggerConfigurationProperties;
import se.swedenconnect.signservice.spring.config.authn.AuthenticationHandlerConfigurationProperties;
import se.swedenconnect.signservice.spring.config.keycert.KeyAndCertificateHandlerConfigurationProperties;
import se.swedenconnect.signservice.spring.config.protocol.ProtocolHandlerConfigurationProperties;
import se.swedenconnect.signservice.spring.config.sign.SignatureHandlerConfigurationProperties;

/**
 * Shared, or default, configuration properties that may be merged into the engine configuration.
 */
public class SharedHandlerConfigurationProperties {

  /**
   * Default/shared protocol handler configuration.
   */
  @Getter
  @Setter
  private ProtocolHandlerConfigurationProperties protocol;

  /**
   * Default/shared authentication handler configuration.
   */
  @Getter
  @Setter
  private AuthenticationHandlerConfigurationProperties authn;

  /**
   * Default/shared signature handler configuration.
   */
  @Getter
  @Setter
  private SignatureHandlerConfigurationProperties sign;

  /**
   * Default/shared key and certificate configuration.
   */
  @Getter
  @Setter
  private KeyAndCertificateHandlerConfigurationProperties cert;

  /**
   * Default/shared audit logger configuration.
   */
  @Getter
  @Setter
  private AuditLoggerConfigurationProperties audit;

}
