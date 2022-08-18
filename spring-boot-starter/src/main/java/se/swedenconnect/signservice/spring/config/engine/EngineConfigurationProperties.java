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
package se.swedenconnect.signservice.spring.config.engine;

import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import lombok.Data;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;
import se.swedenconnect.signservice.client.impl.DefaultClientConfiguration;
import se.swedenconnect.signservice.spring.config.audit.AuditLoggerConfigurationProperties;
import se.swedenconnect.signservice.spring.config.authn.AuthenticationConfigurationProperties;
import se.swedenconnect.signservice.spring.config.protocol.ProtocolConfigurationProperties;

/**
 * Configuration properties for an engine configuration.
 */
@Data
public class EngineConfigurationProperties implements InitializingBean {

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
  private PkiCredentialConfigurationProperties credential;

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
  private ProtocolConfigurationProperties protocol;

  /**
   * Authentication handler configuration.
   */
  private AuthenticationConfigurationProperties authn;

  /**
   * Audit logger configuration.
   */
  private AuditLoggerConfigurationProperties audit;

  // TODO: more settings

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.hasText(this.name, "name must be assigned");
    Assert.notEmpty(this.processingPaths, "processing-paths must be assigned and non-empty");

    Assert.notNull(this.client, "client must be assigned");
    this.client.init();

    Assert.notNull(this.protocol, "protocol must be assigned");
    Assert.notNull(this.authn, "authn must be assigned");
    Assert.notNull(this.audit, "audit must be assigned");
  }

}
