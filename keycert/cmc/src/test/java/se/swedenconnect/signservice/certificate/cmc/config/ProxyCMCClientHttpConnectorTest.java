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

package se.swedenconnect.signservice.certificate.cmc.config;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import se.swedenconnect.ca.cmc.api.client.CMCClientHttpConnector;
import se.swedenconnect.ca.cmc.api.client.impl.HttpProxyConfiguration;
import se.swedenconnect.ca.cmc.api.client.impl.ProxyCMCClientHttpConnector;

/**
 * Basic but limited tests of proxy CMC connector as we have no means to use it.
 */
class ProxyCMCClientHttpConnectorTest {

  @Test
  void createTest() {
    CMCClientHttpConnector defaultConnector = new ProxyCMCClientHttpConnector(null);
    assertNotNull(defaultConnector);
    HttpProxyConfiguration httpProxyConfiguration = new HttpProxyConfiguration();
    httpProxyConfiguration.setHost("127.0.0.1");
    httpProxyConfiguration.setPort(8080);
    httpProxyConfiguration.setUserName("user");
    httpProxyConfiguration.setPassword("password");
    CMCClientHttpConnector proxyConnector = new ProxyCMCClientHttpConnector(httpProxyConfiguration);
    assertNotNull(proxyConnector);
  }
}
