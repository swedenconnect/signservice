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
package se.swedenconnect.signservice.spring.config.protocol;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import se.swedenconnect.signservice.protocol.ProtocolHandler;
import se.swedenconnect.signservice.protocol.dss.DssConfiguration;
import se.swedenconnect.signservice.protocol.dss.DssProtocolHandler;

/**
 * Configuration for protocol handlers.
 */
@Configuration
public class ProtocolConfiguration {

  /** The bean name for the DSS protocol handler. */
  public static final String DSS_PROTOCOL_HANDLER_NAME = "signservice.DssProtocolHandler";

  @Bean("signservice.protocol.dss11.Configuration")
  @ConfigurationProperties(prefix = "signservice.protocol.dss11")
  public DssConfiguration dssConfiguration() {
    return new DssConfiguration();
  }

  @Bean(DSS_PROTOCOL_HANDLER_NAME)
  public ProtocolHandler dssProtocolHandler(
      @Qualifier("signservice.protocol.dss11.Configuration") final DssConfiguration configuration) {
    final DssProtocolHandler handler = new DssProtocolHandler();
    handler.setConfiguration(configuration);
    return handler;
  }

}
