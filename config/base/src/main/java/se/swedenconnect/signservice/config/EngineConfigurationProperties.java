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
package se.swedenconnect.signservice.config;

import java.util.List;

import org.apache.commons.lang3.StringUtils;

import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.signservice.client.impl.DefaultClientConfiguration;
import se.swedenconnect.signservice.config.audit.AuditLoggerConfigurationProperties;
import se.swedenconnect.signservice.config.authn.AuthenticationHandlerConfigurationProperties;
import se.swedenconnect.signservice.config.cert.KeyAndCertificateHandlerConfigurationProperties;
import se.swedenconnect.signservice.config.protocol.ProtocolHandlerConfigurationProperties;
import se.swedenconnect.signservice.config.sign.SignatureHandlerConfigurationProperties;
import se.swedenconnect.signservice.core.config.PkiCredentialConfiguration;

/**
 * Configuration properties for an engine configuration.
 */
@Data
@Slf4j
public class EngineConfigurationProperties {

  /**
   * The name of the engine instance.
   */
  private String name;

  /**
   * The SignService ID.
   */
  private String signServiceId;

  /**
   * The SignService credential.
   */
  private PkiCredentialConfiguration credential;

  /**
   * The engine processing path(s).
   */
  private List<String> processingPaths;

  /**
   * The client configuration.
   */
  private DefaultClientConfiguration client;

  /**
   * Protocol configuration.
   */
  private ProtocolHandlerConfigurationProperties protocol;

  /**
   * Authentication handler configuration.
   */
  private AuthenticationHandlerConfigurationProperties authn;

  /**
   * Signature handler configuration.
   */
  private SignatureHandlerConfigurationProperties sign;

  /**
   * Key and certificate handler configuration.
   */
  private KeyAndCertificateHandlerConfigurationProperties cert;

  /**
   * Audit logger configuration.
   */
  private AuditLoggerConfigurationProperties audit;

  /**
   * Asserts that all required settings have been set.
   *
   * @throws IllegalArgumentException for configuration errors
   */
  @PostConstruct
  public void afterPropertiesSet() throws IllegalArgumentException {
    if (StringUtils.isBlank(this.name)) {
      throw new IllegalArgumentException("name must be assigned");
    }
    if (this.processingPaths == null || this.processingPaths.isEmpty()) {
      throw new IllegalArgumentException("processing-paths must be assigned and non-empty");
    }
    if (this.client == null) {
      throw new IllegalArgumentException("client must be assigned");
    }
    this.client.init();

    if (this.protocol == null) {
      log.debug("protocol not assigned - will attempt to use default bean");
    }
    if (this.authn == null) {
      throw new IllegalArgumentException("authn must be assigned");
    }
    if (this.sign == null) {
      log.debug("sign not assigned - will attempt to use default bean");
    }
    if (this.cert == null) {
      log.debug("cert not assigned - will attempt to use default bean");
    }
    if (this.audit == null) {
      throw new IllegalArgumentException("audit must be assigned");
    }
  }

}
