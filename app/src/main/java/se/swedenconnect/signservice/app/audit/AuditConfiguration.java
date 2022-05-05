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
package se.swedenconnect.signservice.app.audit;

import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.actuate.audit.AuditEventRepository;
import org.springframework.boot.actuate.audit.InMemoryAuditEventRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.signservice.audit.AuditEventIds;
import se.swedenconnect.signservice.audit.AuditLoggerSingleton;
import se.swedenconnect.signservice.audit.base.events.AuditEventFactory;

/**
 * Configuration for Auditing.
 */
@Configuration
@Slf4j
public class AuditConfiguration {

  @Bean
  public AuditEventRepository inMemoryAuditEventRepository() {
    // TODO replace with persistent repository!
    log.warn("Using InMemoryAuditEventRepository, not suitable for production!");
    return new InMemoryAuditEventRepository();
  }

  @Bean
  public SmartInitializingSingleton initialize() {
    return () -> AuditLoggerSingleton.getAuditLogger().auditLog(AuditEventFactory.createAuditEvent(AuditEventIds.EVENT_SYSTEM_STARTED));
  }

}
