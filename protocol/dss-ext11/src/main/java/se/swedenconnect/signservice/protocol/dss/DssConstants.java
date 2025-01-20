/*
 * Copyright 2022-2025 Sweden Connect
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
package se.swedenconnect.signservice.protocol.dss;

/**
 * Defines constants for the DSS protocol.
 */
public class DssConstants {

  /** The DSS profile we use. */
  public static final String DSS_PROFILE = "http://id.elegnamnden.se/csig/1.1/dss-ext/profile";

  /** The namespace for DSS extension. */
  public static final String DSS_EXT_NAMESPACE = "http://id.elegnamnden.se/csig/1.1/dss-ext/ns";

  // Hidden
  private DssConstants() {
  }

}
