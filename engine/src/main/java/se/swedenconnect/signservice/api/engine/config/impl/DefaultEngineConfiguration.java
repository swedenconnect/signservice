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
package se.swedenconnect.signservice.api.engine.config.impl;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.PostConstruct;

import org.apache.commons.lang.StringUtils;

import lombok.Setter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.api.engine.config.EngineConfiguration;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.client.ClientConfiguration;
import se.swedenconnect.signservice.core.http.HttpResourceProvider;
import se.swedenconnect.signservice.protocol.ProtocolHandler;

/**
 * Default implementation of the {@link EngineConfiguration} interface.
 */
public class DefaultEngineConfiguration implements EngineConfiguration {

  /**
   * The engine name.
   *
   * @param name the name of the engine
   */
  @Setter
  private String name;

  /**
   * The unique SignService ID.
   *
   * @param signServiceId the SignService ID
   */
  @Setter
  private String signServiceId;

  /**
   * This engine's SignService credentials.
   *
   * @param signServiceCredential the engine credentials
   */
  @Setter
  private PkiCredential signServiceCredential;

  /**
   * The processing path (relative to the application's context path).
   *
   * @param processingPath the processing path
   */
  @Setter
  private String processingPath;

  /**
   * The protocol handler this engine uses.
   *
   * @param protocolHandler the protocol handler
   */
  @Setter
  private ProtocolHandler protocolHandler;

  /**
   * The authentication handler this engine uses.
   *
   * @param authenticationHandler the authentication handler
   */
  @Setter
  private AuthenticationHandler authenticationHandler;

  /**
   * The key and certificate hander.
   *
   * @param keyAndCertificateHandler key and cert handler
   */
  @Setter
  private KeyAndCertificateHandler keyAndCertificateHandler;

  /**
   * The client configuration.
   *
   * @param clientConfiguration the client configuration
   */
  @Setter
  private ClientConfiguration clientConfiguration;

  /**
   * The engine audit logger.
   *
   * @param auditLogger the engine audit logger
   */
  @Setter
  private AuditLogger auditLogger;

  /**
   * Default constructor.
   */
  public DefaultEngineConfiguration() {
  }

  /**
   * Asserts that all required fields have been assigned.
   *
   * @throws Exception for init errors
   */
  @PostConstruct
  public void init() throws Exception {
    if (StringUtils.isBlank(this.name)) {
      throw new IllegalArgumentException("name must be set");
    }
    if (StringUtils.isBlank(this.signServiceId)) {
      throw new IllegalArgumentException("signServiceId must be set");
    }
    if (this.signServiceCredential == null) {
      throw new IllegalArgumentException("signServiceCredential must be set");
    }
    if (StringUtils.isBlank(this.processingPath)) {
      throw new IllegalArgumentException("processingPath must be set");
    }
    if (this.protocolHandler == null) {
      throw new IllegalArgumentException("protocolHandler must be set");
    }
    if (this.authenticationHandler == null) {
      throw new IllegalArgumentException("authenticationHandler must be set");
    }
    if (this.keyAndCertificateHandler == null) {
      throw new IllegalArgumentException("keyAndCertificateHandler must be set");
    }
    if (this.clientConfiguration == null) {
      throw new IllegalArgumentException("clientConfiguraton must be set");
    }
    if (this.auditLogger == null) {
      throw new IllegalArgumentException("auditLogger must be set");
    }
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return this.name;
  }

  /** {@inheritDoc} */
  @Override
  public String getSignServiceId() {
    return this.signServiceId;
  }

  /** {@inheritDoc} */
  @Override
  public PkiCredential getSignServiceCredential() {
    return this.signServiceCredential;
  }

  /** {@inheritDoc} */
  @Override
  public String getProcessingPath() {
    return this.processingPath;
  }

  /** {@inheritDoc} */
  @Override
  public ProtocolHandler getProtocolHandler() {
    return this.protocolHandler;
  }

  /** {@inheritDoc} */
  @Override
  public AuthenticationHandler getAuthenticationHandler() {
    return this.authenticationHandler;
  }

  /** {@inheritDoc} */
  @Override
  public KeyAndCertificateHandler getKeyAndCertificateHandler() {
    return this.keyAndCertificateHandler;
  }

  /** {@inheritDoc} */
  @Override
  public ClientConfiguration getClientConfiguration() {
    return this.clientConfiguration;
  }

  /** {@inheritDoc} */
  @Override
  public AuditLogger getAuditLogger() {
    return this.auditLogger;
  }

  /** {@inheritDoc} */
  @Override
  public List<HttpResourceProvider> getHttpResourceProviders() {
    final List<HttpResourceProvider> providers = new ArrayList<>();
    if (this.authenticationHandler != null && HttpResourceProvider.class.isInstance(this.authenticationHandler)) {
      providers.add(HttpResourceProvider.class.cast(this.authenticationHandler));
    }
    if (this.keyAndCertificateHandler != null && HttpResourceProvider.class.isInstance(this.keyAndCertificateHandler)) {
      providers.add(HttpResourceProvider.class.cast(this.keyAndCertificateHandler));
    }
    if (this.protocolHandler != null && HttpResourceProvider.class.isInstance(this.protocolHandler)) {
      providers.add(HttpResourceProvider.class.cast(this.protocolHandler));
    }
    return providers;
  }

}
