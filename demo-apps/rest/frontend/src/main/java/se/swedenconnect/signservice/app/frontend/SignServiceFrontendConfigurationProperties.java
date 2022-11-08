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
package se.swedenconnect.signservice.app.frontend;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

/**
 * Configuration properties for the SignService Frontend application.
 */
@Data
@ConfigurationProperties(prefix = "signservice.frontend")
public class SignServiceFrontendConfigurationProperties {

  /**
   * The base URL to the backend server (protocol, host and context path).
   */
  private String backendUrl;

  /**
   * The path to where we should post our requests (relative to {@code backendUrl}).
   */
  private String processPath;

}
