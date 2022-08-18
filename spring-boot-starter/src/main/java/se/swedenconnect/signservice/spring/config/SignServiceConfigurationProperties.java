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

import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;
import se.swedenconnect.signservice.spring.config.audit.AuditLoggerConfigurationProperties;
import se.swedenconnect.signservice.spring.config.engine.EngineConfigurationProperties;

/**
 * Configuration properties for SignService configuration.
 */
@ConfigurationProperties("signservice")
@Data
@Slf4j
public class SignServiceConfigurationProperties implements InitializingBean {

  /**
   * The domain under which the SignService is running.
   */
  private String domain;

  /**
   * The "base URL" of the SignService, i.e., everything up until the context path. If not explicitly set, the value is
   * set to https://${signservice.domain}.
   */
  private String baseUrl;

  /**
   * The SignService default credential. By setting this, several engines may share the same credential.
   */
  private PkiCredentialConfigurationProperties defaultCredential;

  /**
   * Default handler configuration. Used by the handler instances configured as part of the engine configuration.
   */
  private SharedHandlerConfigurationProperties defaultHandlerConfig;

  /**
   * System audit logger configuration.
   */
  private AuditLoggerConfigurationProperties systemAudit;

  /**
   * A list of engine configurations.
   */
  private List<EngineConfigurationProperties> engines;

  /**
   * Assigns default values to properties that are not explicitly set and needs to have non-static values.
   */
  @Override
  public void afterPropertiesSet() throws Exception {
    if (!StringUtils.hasText(this.domain)) {
      this.domain = "localhost";
      log.warn("signservice.domain not set, using {}", this.domain);
    }
    if (!StringUtils.hasText(this.baseUrl)) {
      this.baseUrl = String.format("https://%s", this.domain);
      log.info("signservice.base-url not set, using default: {}", this.baseUrl);
    }
    Assert.notNull(this.systemAudit, "signservice.system-audit.* must be set");
    // Assert we have a configuration ...
    this.systemAudit.getHandlerConfiguration();

    if (this.engines != null) {
      for (final EngineConfigurationProperties e : this.engines) {
        e.afterPropertiesSet();
      }
    }
  }
}
