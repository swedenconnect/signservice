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
package se.swedenconnect.signservice.config;

import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.PostConstruct;

import org.apache.commons.lang3.StringUtils;

import lombok.Setter;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.signservice.config.audit.AuditLoggerConfigurationProperties;
import se.swedenconnect.signservice.config.common.CommonBeansConfigurationProperties;
import se.swedenconnect.signservice.core.config.PkiCredentialConfiguration;
import se.swedenconnect.signservice.session.SessionHandler;
import se.swedenconnect.signservice.session.impl.DefaultSessionHandler;
import se.swedenconnect.signservice.storage.impl.DefaultMessageReplayChecker;
import se.swedenconnect.signservice.storage.impl.ReplayCheckerStorageContainer;

/**
 * Default implementation of {@link SignServiceConfigurationProperties}.
 */
public class DefaultSignServiceConfigurationProperties implements SignServiceConfigurationProperties {

  /**
   * The domain under which the SignService is running.
   */
  @Setter
  private String domain;

  /**
   * The "base URL" of the SignService, i.e., the protocol, domain and context path (if set to something other than
   * '/'). Must not end with a '/'.
   */
  @Setter
  private String baseUrl;

  /**
   * The default SignService ID. May be overridden in engines.
   */
  @Setter
  private String defaultSignServiceId;

  /**
   * Configuration for the SignService default credential. By setting this, several engines may share the same credential.
   */
  @Setter
  private PkiCredentialConfiguration defaultCredential;

  /**
   * Common beans configuration.
   */
  @Setter
  private CommonBeansConfigurationProperties commonBeans;

  /**
   * Default handler configuration. Used by the handler instances configured as part of the engine configuration.
   */
  @Setter
  private SharedHandlerConfigurationProperties defaultHandlerConfig;

  /**
   * System audit logger configuration.
   */
  @Setter
  private AuditLoggerConfigurationProperties systemAudit;

  /**
   * The bean name of the {@link SessionHandler} that should be used by the SignService application. If not assigned, a
   * {@link DefaultSessionHandler} instance will be used.
   */
  @Setter
  private String sessionHandlerBeanName;

  /**
   * Refers to a {@link MessageReplayChecker} bean that will be used by the application to detect message replay
   * attacks. If not set, a {@link DefaultMessageReplayChecker} will be used.
   */
  @Setter
  private String messageReplayCheckerBeanName;

  /**
   * Relevant only if {@code message-replay-checker-bean-name} is not set. In these cases a
   * {@link DefaultMessageReplayChecker} will be created using a {@link ReplayCheckerStorageContainer} instance. This
   * setting refers to {@link ReplayCheckerStorageContainer} bean.
   */
  @Setter
  private String replayCheckerStorageContainerBeanName;

  /**
   * A list of engine configurations.
   */
  @Setter
  private List<EngineConfigurationProperties> engines;

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getDomain() {
    return this.domain;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getBaseUrl() {
    return this.baseUrl;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public String getDefaultSignServiceId() {
    return this.defaultSignServiceId;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public PkiCredentialConfiguration getDefaultCredential() {
    return this.defaultCredential;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public CommonBeansConfigurationProperties getCommonBeans() {
    return this.commonBeans;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public SharedHandlerConfigurationProperties getDefaultHandlerConfig() {
    return this.defaultHandlerConfig;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public AuditLoggerConfigurationProperties getSystemAudit() {
    return this.systemAudit;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public String getSessionHandlerBeanName() {
    return this.sessionHandlerBeanName;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public String getMessageReplayCheckerBeanName() {
    return this.messageReplayCheckerBeanName;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public String getReplayCheckerStorageContainerBeanName() {
    return this.replayCheckerStorageContainerBeanName;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public List<EngineConfigurationProperties> getEngines() {
    return this.engines;
  }

  /** {@inheritDoc} */
  @Override
  @PostConstruct
  public void afterPropertiesSet() throws IllegalArgumentException {
    if (StringUtils.isBlank(this.domain)) {
      throw new IllegalArgumentException("signservice.domain must be set");
    }
    if (StringUtils.isBlank(this.baseUrl)) {
      throw new IllegalArgumentException("signservice.base-url must be set");
    }
    if (this.systemAudit == null) {
      throw new IllegalArgumentException("signservice.system-audit.* must be set");
    }
    this.systemAudit.getHandlerConfiguration();

    if (this.commonBeans != null) {
      this.commonBeans.afterPropertiesSet();
    }
    if (this.engines != null) {
      for (final EngineConfigurationProperties e : this.engines) {
        e.afterPropertiesSet();
      }
    }
  }

}
