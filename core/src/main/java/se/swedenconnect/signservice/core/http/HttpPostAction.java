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
package se.swedenconnect.signservice.core.http;

import java.util.Map;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import jakarta.annotation.Nonnull;

/**
 * Represents a HTTP post action where the user's browser is posted to the given URL along with the parameters.
 */
@JsonDeserialize(as = DefaultHttpPostAction.class)
public interface HttpPostAction {

  /**
   * Gets the URL to which the user's browser should be posted to.
   *
   * @return the URL
   */
  @Nonnull
  String getUrl();

  /**
   * The request parameters that should be posted to the recipient. The parameters are represented using a Map where the
   * entries represent parameter names and values.
   * <p>
   * The values in the map are not URL-encoded, so before using any values in the resulting map the values must be
   * encoded.
   * </p>
   *
   * @return a (possibly empty) Map holding the HTTP request parameters
   */
  @Nonnull
  Map<String, String> getParameters();
}
