/*
 * Copyright 2022-2023 Sweden Connect
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
package se.swedenconnect.signservice.config;

import java.util.List;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.annotation.PostConstruct;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.signservice.config.audit.AuditLoggerConfigurationProperties;
import se.swedenconnect.signservice.config.common.CommonBeansConfigurationProperties;
import se.swedenconnect.signservice.core.config.PkiCredentialConfiguration;
import se.swedenconnect.signservice.core.config.ValidationConfiguration;
import se.swedenconnect.signservice.storage.impl.DefaultMessageReplayChecker;
import se.swedenconnect.signservice.storage.impl.InMemoryReplayCheckerStorageContainer;
import se.swedenconnect.signservice.storage.impl.ReplayCheckerStorageContainer;

/**
 * Interface describing all configuration settings for setting up a SignService application.
 */
public interface SignServiceConfigurationProperties {

  /**
   * The domain under which the SignService is running.
   *
   * @return SignService domain
   */
  @Nonnull
  String getDomain();

  /**
   * The "base URL" of the SignService, i.e., the protocol, domain and context path (if set to something other than
   * '/'). Must not end with a '/'.
   *
   * @return the application base URL
   */
  @Nonnull
  String getBaseUrl();

  /**
   * The default SignService ID. May be overridden in engines. If {@code null}, all engines must define a SignService
   * ID.
   *
   * @return the default SignService ID
   */
  @Nullable
  String getDefaultSignServiceId();

  /**
   * Configuration for the SignService default credential. By setting this, several engines may share the same
   * credential. If {@code null}, all engines must define a SignService credential.
   *
   * @return default SignService credential
   */
  @Nullable
  PkiCredentialConfiguration getDefaultCredential();

  /**
   * Configuration for application wide validation settings.
   * <p>
   * If no validation settings are configured a default instance of {@link ValidationConfiguration} will be used.
   * </p>
   *
   * @return validation configuration
   */
  @Nullable
  ValidationConfiguration getValidationConfig();

  /**
   * Common beans configuration.
   *
   * @return the common beans configuration
   */
  @Nullable
  CommonBeansConfigurationProperties getCommonBeans();

  /**
   * Default handler configuration. Used by the handler instances configured as part of the engine configuration.
   *
   * @return default handler configuration
   */
  @Nullable
  SharedHandlerConfigurationProperties getDefaultHandlerConfig();

  /**
   * System audit logger configuration.
   *
   * @return the system audit configuration
   */
  @Nonnull
  AuditLoggerConfigurationProperties getSystemAudit();

  /**
   * Refers to a {@link MessageReplayChecker} bean that will be used by the application to detect message replay
   * attacks. If not set, a {@link DefaultMessageReplayChecker} will be used.
   *
   * @return the bean name or null
   * @see #getReplayCheckerStorageContainerBeanName()
   */
  @Nullable
  String getMessageReplayCheckerBeanName();

  /**
   * Relevant only if {@code message-replay-checker-bean-name} is not set. In these cases a
   * {@link DefaultMessageReplayChecker} will be created using a {@link ReplayCheckerStorageContainer} instance. This
   * setting refers to {@link ReplayCheckerStorageContainer} bean.
   * <p>
   * If this setting is {@code null} an {@link InMemoryReplayCheckerStorageContainer} instance will be used. This is not
   * advisable in a distributed application setup (i.e., when several instances of the SignService application is
   * running).
   * </p>
   *
   * @return the bean name of null
   */
  @Nullable
  String getReplayCheckerStorageContainerBeanName();

  /**
   * A list of engine configurations.
   *
   * @return the SignService engine instances
   */
  @Nonnull
  List<EngineConfigurationProperties> getEngines();

  /**
   * Assigns default values to properties that are not explicitly set and needs to have non-static values and also
   * checks that mandatory values have been assigned.
   *
   * @throws IllegalArgumentException for configuration errors
   */
  @PostConstruct
  void afterPropertiesSet() throws IllegalArgumentException;

}
