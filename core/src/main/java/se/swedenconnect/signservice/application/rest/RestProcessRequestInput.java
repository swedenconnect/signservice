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
package se.swedenconnect.signservice.application.rest;

import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.signservice.core.http.HttpUserRequest;

/**
 * A class that represents the "process request" input data that is put together by a REST client (i.e., the SignService
 * frontend) and is consumed by the SignService backend.
 */
@JsonInclude(Include.NON_NULL)
public class RestProcessRequestInput {

  /** The string representation of the SignService context. */
  @Getter
  @Setter
  private String context;

  /** The mapping of the HTTP request that was received by the frontend application. */
  @Getter
  @Setter
  private HttpUserRequest userRequest;

  /**
   * Default constructor.
   */
  public RestProcessRequestInput() {
  }

  /**
   * Constructor assigning the input parameters.
   *
   * @param context the string representation of the SignService context (may be null)
   * @param userRequest the mapping of the incoming HTTP request
   */
  public RestProcessRequestInput(
      @Nullable final String context,
      @Nonnull final HttpUserRequest userRequest) {
    this.context = context;
    this.userRequest = Objects.requireNonNull(userRequest, "userRequest must not be null");
  }

}
