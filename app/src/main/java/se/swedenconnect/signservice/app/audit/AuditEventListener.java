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

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.AuditEventRepository;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Audit Event Listener
 */
@Component
@Slf4j
public class AuditEventListener {

  /**
   * AuditEventRepository
   */
  @Autowired
  private AuditEventRepository auditEventRepository;

  /**
   * Add an audit event to the event repository
   * @param event - The audit event
   */
  @EventListener
  public void onAuditEvent(AuditEvent event) {
    auditEventRepository.add(event);
  }

}
