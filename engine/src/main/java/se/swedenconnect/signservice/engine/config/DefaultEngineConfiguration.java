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
package se.swedenconnect.signservice.engine.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import jakarta.annotation.PostConstruct;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.client.ClientConfiguration;
import se.swedenconnect.signservice.core.http.HttpResourceProvider;
import se.swedenconnect.signservice.protocol.ProtocolHandler;
import se.swedenconnect.signservice.signature.SignatureHandler;

/**
 * Default implementation of the {@link EngineConfiguration} interface.
 */
public class DefaultEngineConfiguration implements EngineConfiguration {

  /** The engine name. */
  private String name;

  /** The unique SignService ID. */
  private String signServiceId;

  /** This engine's SignService credentials. */
  private PkiCredential signServiceCredential;

  /** The processing paths (relative to the application's context path). */
  private List<String> processingPaths;

  /** The protocol handler this engine uses. */
  private ProtocolHandler protocolHandler;

  /** The authentication handler this engine uses. */
  private AuthenticationHandler authenticationHandler;

  /** The key and certificate hander. */
  private KeyAndCertificateHandler keyAndCertificateHandler;

  /** The signature handler. */
  private SignatureHandler signatureHandler;

  /** The client configuration. */
  private ClientConfiguration clientConfiguration;

  /** The engine audit logger. */
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
    if (this.processingPaths == null || this.processingPaths.isEmpty()) {
      throw new IllegalArgumentException("processingPaths must be set");
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
    if (this.signatureHandler == null) {
      throw new IllegalArgumentException("signatureHandler must be set");
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

  /**
   * Assigns the engine name.
   *
   * @param name the name of the engine
   */
  public void setName(final String name) {
    this.name = name;
  }


  /** {@inheritDoc} */
  @Override
  public String getSignServiceId() {
    return this.signServiceId;
  }

  /**
   * Assigns the unique SignService ID.
   *
   * @param signServiceId the SignService ID
   */
  public void setSignServiceId(final String signServiceId) {
    this.signServiceId = signServiceId;
  }


  /** {@inheritDoc} */
  @Override
  public PkiCredential getSignServiceCredential() {
    return this.signServiceCredential;
  }

  /**
   * Assigns this engine's SignService credentials.
   *
   * @param signServiceCredential the engine credentials
   */
  public void setSignServiceCredential(final PkiCredential signServiceCredential) {
    this.signServiceCredential = signServiceCredential;
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getProcessingPaths() {
    return this.processingPaths != null ? Collections.unmodifiableList(this.processingPaths) : null;
  }

  /**
   * Assigns the processing paths (relative to the application's context path).
   *
   * @param processingPaths the processing paths
   */
  public void setProcessingPaths(final List<String> processingPaths) {
    this.processingPaths = processingPaths;
  }

  /** {@inheritDoc} */
  @Override
  public ProtocolHandler getProtocolHandler() {
    return this.protocolHandler;
  }

  /**
   * Assigns the protocol handler this engine uses.
   *
   * @param protocolHandler the protocol handler
   */
  public void setProtocolHandler(final ProtocolHandler protocolHandler) {
    this.protocolHandler = protocolHandler;
  }

  /** {@inheritDoc} */
  @Override
  public AuthenticationHandler getAuthenticationHandler() {
    return this.authenticationHandler;
  }

  /**
   * Assigns the authentication handler this engine uses.
   *
   * @param authenticationHandler the authentication handler
   */
  public void setAuthenticationHandler(final AuthenticationHandler authenticationHandler) {
    this.authenticationHandler = authenticationHandler;
  }

  /** {@inheritDoc} */
  @Override
  public KeyAndCertificateHandler getKeyAndCertificateHandler() {
    return this.keyAndCertificateHandler;
  }

  /**
   * Assigns the key and certificate hander.
   *
   * @param keyAndCertificateHandler key-and-certificate handler
   */
  public void setKeyAndCertificateHandler(final KeyAndCertificateHandler keyAndCertificateHandler) {
    this.keyAndCertificateHandler = keyAndCertificateHandler;
  }

  /** {@inheritDoc} */
  @Override
  public SignatureHandler getSignatureHandler() {
    return this.signatureHandler;
  }

  /**
   * Assigns the signature handler.
   *
   * @param signatureHandler the signature handler
   */
  public void setSignatureHandler(final SignatureHandler signatureHandler) {
    this.signatureHandler = signatureHandler;
  }

  /** {@inheritDoc} */
  @Override
  public ClientConfiguration getClientConfiguration() {
    return this.clientConfiguration;
  }

  /**
   * Assigns the client configuration.
   *
   * @param clientConfiguration the client configuration
   */
  public void setClientConfiguration(final ClientConfiguration clientConfiguration) {
    this.clientConfiguration = clientConfiguration;
  }

  /** {@inheritDoc} */
  @Override
  public AuditLogger getAuditLogger() {
    return this.auditLogger;
  }

  /**
   * Assigns the engine audit logger.
   *
   * @param auditLogger the engine audit logger
   */
  public void setAuditLogger(final AuditLogger auditLogger) {
    this.auditLogger = auditLogger;
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
