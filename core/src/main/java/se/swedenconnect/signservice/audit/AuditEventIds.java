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
package se.swedenconnect.signservice.audit;

/**
 * Defines audit logger events identifiers.
 */
public class AuditEventIds {

  /** SignService system was started. */
  public final static String EVENT_SYSTEM_STARTED = "audit.system.started";

  /** A SignService engine instance (servicing a client) was started. */
  public final static String EVENT_ENGINE_STARTED = "audit.engine.started";

  // TODO: More

  // Hidden constructor
  private AuditEventIds() {
  }

}
