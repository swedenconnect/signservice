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
package se.swedenconnect.signservice.api.engine.config;

import java.util.List;

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.api.audit.AuditLogger;
import se.swedenconnect.signservice.api.authn.AuthenticationHandler;
import se.swedenconnect.signservice.api.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.api.client.ClientConfiguration;
import se.swedenconnect.signservice.api.protocol.ProtocolHandler;
import se.swedenconnect.signservice.api.session.SessionHandler;
import se.swedenconnect.signservice.api.storage.MessageReplayChecker;
import se.swedenconnect.signservice.core.http.HttpResourceProvider;

/**
 * Interface defining the configuration API for an engine instance.
 */
public interface EngineConfiguration {

  /**
   * Gets the name of this engine instance. This is used for logging.
   *
   * @return the engine name
   */
  String getName();

  /**
   * Gets the unique ID for this SignService engine instance.
   *
   * @return the SignService identifier for the instance
   */
  String getSignServiceId();

  /**
   * Gets the credential that this SignService uses to sign reponse messages with.
   *
   * @return a credential
   */
  PkiCredential getSignServiceCredential();

  /**
   * Gets the path (relative the application root) for the SignRequest processing endpoint.
   *
   * @return the processing path
   */
  String getProcessingPath();

  /**
   * Gets the session handler this instance uses.
   *
   * @return the session handler
   */
  SessionHandler getSessionHandler();

  /**
   * Gets the message replay checker to use by the engine instance.
   *
   * @return a message replay checker
   */
  MessageReplayChecker getMessageReplayChecker();

  /**
   * Gets the protocol handler to use when decoding and encoding messages.
   *
   * @return the protocol handler
   */
  ProtocolHandler getProtocolHandler();

  /**
   * Gets the authentication handler to use when authenticating the users.
   *
   * @return the authentication handler
   */
  AuthenticationHandler getAuthenticationHandler();

  /**
   * Gets the key and certificate handler that is used to generate the user signing key and certificate.
   *
   * @return the key and certificate handler
   */
  KeyAndCertificateHandler getKeyAndCertificateHandler();

  /**
   * Gets the configuration for the SignService client that is being serviced by this SignService engine.
   *
   * @return the client configuration
   */
  ClientConfiguration getClientConfiguration();

  /**
   * Gets the audit logger to use.
   *
   * @return the audit logger
   */
  AuditLogger getAuditLogger();

  /**
   * Gets a list of all handlers that implements the {@link HttpResourceProvider} interface.
   *
   * @return a list of HTTP resource providers
   */
  List<HttpResourceProvider> getHttpResourceProviders();

}
