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
import org.springframework.util.StringUtils;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;
import se.swedenconnect.signservice.spring.config.protocol.ProtocolConfiguration;

/**
 * Configuration properties for an engine configuration.
 */
@Data
@Slf4j
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
  private ClientConfigurationProperties client;

  /**
   * The name of the protocol handler bean to use for this engine.
   */
  private String protocolHandlerBean;

  // TODO: more settings

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.hasText(this.name, "name must be assigned");
    Assert.hasText(this.signServiceId, "sign-service-id must be assigned");
    Assert.notEmpty(this.processingPaths, "processing-paths must be assigned and non-empty");

    Assert.notNull(client, "client must be assigned");
    this.client.afterPropertiesSet();

    if (!StringUtils.hasText(this.protocolHandlerBean)) {
      log.info("protocol-handler-bean has not been assigned, using {}",
          ProtocolConfiguration.DSS_PROTOCOL_HANDLER_NAME);
      this.protocolHandlerBean = ProtocolConfiguration.DSS_PROTOCOL_HANDLER_NAME;
    }
  }

}