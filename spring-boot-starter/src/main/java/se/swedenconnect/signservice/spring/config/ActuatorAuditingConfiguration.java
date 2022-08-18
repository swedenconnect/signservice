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
package se.swedenconnect.signservice.spring.config;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.audit.AuditEventRepository;
import org.springframework.boot.actuate.audit.InMemoryAuditEventRepository;
import org.springframework.boot.actuate.audit.listener.AuditListener;
import org.springframework.boot.autoconfigure.AutoConfigureOrder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.signservice.audit.actuator.ActuatorAuditLogger;
import se.swedenconnect.signservice.spring.config.engine.EngineConfigurationProperties;

/**
 * Configuration class setting up required beans for using Spring Boot's actuator audit logging.
 */
@AutoConfigureOrder(Ordered.HIGHEST_PRECEDENCE)
@Configuration
@EnableConfigurationProperties(SignServiceConfigurationProperties.class)
@Slf4j
public class ActuatorAuditingConfiguration implements InitializingBean {

  /** The SignService configuration properties. */
  @Setter
  @Autowired
  private SignServiceConfigurationProperties properties;

  /** Flag telling whether actuator auditing is configued. */
  private boolean actuatorAuditingConfigured = false;

  /**
   * If at least one {@link ActuatorAuditLogger} is defined, a {@link AuditEventRepository} been is needed. This method
   * ensures that this bean is created, if not already defined.
   *
   * @return a AuditEventRepository or null if none is needed
   */
  @ConditionalOnMissingBean
  @Bean
  public AuditEventRepository auditEventRepository() {
    if (!this.actuatorAuditingConfigured) {
      return null;
    }
    log.info("At least one ActuatorAuditLogger instance is in use, but no AuditEventRepository is present - "
        + "creating " + InMemoryAuditEventRepository.class.getSimpleName());
    return new InMemoryAuditEventRepository();
  }

  /**
   * If at least one {@link ActuatorAuditLogger} is defined, an audit listener bean named
   * {@code signservice.AuditListener} is needed. If this has not been defined, this method creates it.
   *
   * @param auditEventRepository the event repository
   * @return an AuditListener or null if none is needed
   */
  @ConditionalOnBean(AuditEventRepository.class)
  @ConditionalOnMissingBean(name = "signservice.AuditListener")
  @Bean("signservice.AuditListener")
  public AuditListener auditListener(
      final AuditEventRepository auditEventRepository) {

    if (!this.actuatorAuditingConfigured) {
      return null;
    }
    log.info("At least one ActuatorAuditLogger instance is in use, but no \"signservice.AuditListener\" "
        + "has been defined - creating " + AuditListener.class.getSimpleName());
    return new AuditListener(auditEventRepository);
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    this.actuatorAuditingConfigured = this.properties.getSystemAudit().getActuator() != null
        && this.properties.getSystemAudit().getActuator().isActive();
    if (!this.actuatorAuditingConfigured) {
      for (final EngineConfigurationProperties e : this.properties.getEngines()) {
        if (e.getAudit().getActuator() != null && e.getAudit().getActuator().isActive()) {
          this.actuatorAuditingConfigured = true;
          return;
        }
      }
    }
  }

}
