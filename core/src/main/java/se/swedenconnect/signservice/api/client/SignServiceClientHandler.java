/*
 * Copyright 2022 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package se.swedenconnect.signservice.api.client;

/**
 * The client handler is responsible of handling the SignService client configuration.
 */
public interface SignServiceClientHandler {

  /**
   * Gets the unique client identifier that this handler services.
   *
   * @return the client id
   */
  String getClientId();

  // TODO: certificates, response URL:s, ...

}