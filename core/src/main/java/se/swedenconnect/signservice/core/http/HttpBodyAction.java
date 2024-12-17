/*
 * Copyright 2022-2024 Sweden Connect
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
package se.swedenconnect.signservice.core.http;

import java.util.Map;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import jakarta.annotation.Nonnull;

/**
 * The {@code HttpBodyAction} is used when a SignService handler processes a request and wants to write a response body
 * (that is later written to the HTTP response).
 * <p>
 * Note: This action is only used for successful HTTP Status (200) responses.
 * </p>
 */
@JsonDeserialize(as = DefaultHttpBodyAction.class)
public interface HttpBodyAction {

  /**
   * Gets the response body to write as a byte array.
   *
   * @return the response body
   */
  @Nonnull
  byte[] getContents();

  /**
   * Gets a map of header names and values, for example, "Content-Type".
   *
   * @return a (possibly empty) map of headers
   */
  @Nonnull
  Map<String, String> getHeaders();

}
