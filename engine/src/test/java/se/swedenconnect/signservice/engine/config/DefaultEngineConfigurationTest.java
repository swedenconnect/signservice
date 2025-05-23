/*
 * Copyright 2022-2025 Sweden Connect
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
package se.swedenconnect.signservice.engine.config;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.factory.KeyStoreBuilder;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.client.ClientConfiguration;
import se.swedenconnect.signservice.client.impl.DefaultClientConfiguration;
import se.swedenconnect.signservice.core.http.HttpResourceProvider;
import se.swedenconnect.signservice.protocol.ProtocolHandler;
import se.swedenconnect.signservice.signature.SignatureHandler;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * Test cases for DefaultEngineConfiguration.
 */
public class DefaultEngineConfigurationTest {

  @Test
  public void testSetterAndGetter() throws Exception {
    final DefaultEngineConfiguration config = new DefaultEngineConfiguration();

    assertThatThrownBy(config::init).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("name must be set");
    config.setName("Engine");
    Assertions.assertEquals("Engine", config.getName());

    assertThatThrownBy(config::init).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("signServiceId must be set");
    config.setSignServiceId("ID");
    Assertions.assertEquals("ID", config.getSignServiceId());

    assertThatThrownBy(config::init).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("signServiceCredential must be set");
    config.setSignServiceCredential(new KeyStoreCredential(KeyStoreBuilder.builder()
        .location("classpath:keys.jks").password("secret").build(),
        "sign", "secret".toCharArray()));
    Assertions.assertNotNull(config.getSignServiceCredential());

    assertThatThrownBy(config::init).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("processingPaths must be set");

    Assertions.assertNull(config.getProcessingPaths());
    config.setProcessingPaths(Collections.emptyList());

    assertThatThrownBy(config::init).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("processingPaths must be set");
    config.setProcessingPaths(List.of("/path"));
    Assertions.assertEquals(List.of("/path"), config.getProcessingPaths());

    Assertions.assertTrue(config.getHttpResourceProviders().isEmpty());

    assertThatThrownBy(config::init).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("protocolHandler must be set");
    final ProtocolHandler protocolHandler = Mockito.mock(ProtocolHandler.class);
    config.setProtocolHandler(protocolHandler);
    Assertions.assertNotNull(config.getProtocolHandler());

    Assertions.assertTrue(config.getHttpResourceProviders().isEmpty());

    final ProtocolHandler protocolHandler2 = Mockito.mock(ProtocolHandler.class,
        Mockito.withSettings().extraInterfaces(HttpResourceProvider.class));
    config.setProtocolHandler(protocolHandler2);
    Assertions.assertNotNull(config.getProtocolHandler());

    Assertions.assertTrue(config.getHttpResourceProviders().size() == 1);

    assertThatThrownBy(config::init).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("authenticationHandler must be set");
    final AuthenticationHandler authnHandler = Mockito.mock(AuthenticationHandler.class);
    config.setAuthenticationHandler(authnHandler);
    Assertions.assertNotNull(config.getAuthenticationHandler());

    Assertions.assertTrue(config.getHttpResourceProviders().size() == 1);

    final AuthenticationHandler authnHandler2 = Mockito.mock(AuthenticationHandler.class,
        Mockito.withSettings().extraInterfaces(HttpResourceProvider.class));
    config.setAuthenticationHandler(authnHandler2);
    Assertions.assertNotNull(config.getAuthenticationHandler());

    Assertions.assertTrue(config.getHttpResourceProviders().size() == 2);

    assertThatThrownBy(config::init).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("keyAndCertificateHandler must be set");
    final KeyAndCertificateHandler certHandler = Mockito.mock(KeyAndCertificateHandler.class);
    config.setKeyAndCertificateHandler(certHandler);
    Assertions.assertNotNull(config.getKeyAndCertificateHandler());

    Assertions.assertTrue(config.getHttpResourceProviders().size() == 2);

    final KeyAndCertificateHandler certHandler2 = Mockito.mock(KeyAndCertificateHandler.class,
        Mockito.withSettings().extraInterfaces(HttpResourceProvider.class));
    config.setKeyAndCertificateHandler(certHandler2);
    Assertions.assertNotNull(config.getKeyAndCertificateHandler());

    Assertions.assertTrue(config.getHttpResourceProviders().size() == 3);

    assertThatThrownBy(config::init).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("signatureHandler must be set");
    final SignatureHandler sigHandler = Mockito.mock(SignatureHandler.class);
    config.setSignatureHandler(sigHandler);
    Assertions.assertNotNull(config.getSignatureHandler());

    assertThatThrownBy(config::init).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("clientConfiguraton must be set");
    final ClientConfiguration clientConf = new DefaultClientConfiguration();
    config.setClientConfiguration(clientConf);
    Assertions.assertEquals(clientConf, config.getClientConfiguration());

    assertThatThrownBy(config::init).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("auditLogger must be set");
    final AuditLogger audit = Mockito.mock(AuditLogger.class);
    config.setAuditLogger(audit);
    Assertions.assertNotNull(config.getAuditLogger());

    assertDoesNotThrow(config::init);
  }
}
