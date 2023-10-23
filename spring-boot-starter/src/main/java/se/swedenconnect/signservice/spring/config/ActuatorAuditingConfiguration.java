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
package se.swedenconnect.signservice.spring.config;

import org.springframework.boot.actuate.audit.AuditEventRepository;
import org.springframework.boot.actuate.audit.InMemoryAuditEventRepository;
import org.springframework.boot.actuate.audit.listener.AuditListener;
import org.springframework.boot.autoconfigure.AutoConfigureOrder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import lombok.extern.slf4j.Slf4j;

/**
 * Configuration class setting up required beans for using Spring Boot's actuator audit logging.
 */
@AutoConfigureOrder(Ordered.HIGHEST_PRECEDENCE)
@Configuration
@Slf4j
public class ActuatorAuditingConfiguration {

  /**
   * An {@link AuditEventRepository} been is needed to audit log using the Spring actuator. This method ensures that
   * this bean is created, if not already defined.
   *
   * @return an AuditEventRepository bean
   */
  @ConditionalOnMissingBean
  @Bean
  public AuditEventRepository auditEventRepository() {
    log.info("No AuditEventRepository is present - creating " + InMemoryAuditEventRepository.class.getSimpleName());
    return new InMemoryAuditEventRepository();
  }

  /**
   * In order to support audit logging using Spring actuator we need an audit listener bean named
   * {@code signservice.AuditListener}. If this has not been defined, this method creates it.
   *
   * @param auditEventRepository the event repository
   * @return an AuditListener
   */
  @ConditionalOnBean(AuditEventRepository.class)
  @ConditionalOnMissingBean(name = "signservice.AuditListener")
  @Bean("signservice.AuditListener")
  public AuditListener auditListener(
      final AuditEventRepository auditEventRepository) {
    log.info("No \"signservice.AuditListener\" has been defined - creating " + AuditListener.class.getSimpleName());
    return new AuditListener(auditEventRepository);
  }

}
