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
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import jakarta.annotation.Nonnull;
import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.signservice.application.SignServiceProcessingResult;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.http.HttpResponseAction;

/**
 * A representation of a {@link SignServiceProcessingResult} that is suitable to use when setting up the Signature
 * Service as frontend and backend services and where the fronend calls the backend service using REST calls.
 */
@JsonInclude(Include.NON_NULL)
public class RestProcessRequestResult {

  /** The string representation of the SignService context. */
  @Getter
  @Setter
  private String context;

  /**
   * The response action. See {@link SignServiceProcessingResult#getResponseAction()}.
   */
  @Getter
  @Setter
  private HttpResponseAction responseAction;

  /**
   * Default constructor.
   */
  public RestProcessRequestResult() {
  }

  /**
   * A constructor that maps a {@link SignServiceProcessingResult} to a {@code RestProcessRequestResult} object.
   *
   * @param result a SignServiceProcessingResult object
   */
  public RestProcessRequestResult(@Nonnull final SignServiceProcessingResult result) {
    Objects.requireNonNull(result, "result must not be null");

    this.responseAction = Optional.ofNullable(result.getResponseAction())
        .orElseThrow(() -> new IllegalArgumentException("No response action present"));
    this.context = Optional.ofNullable(result.getSignServiceContext())
        .map(SignServiceContext::serialize)
        .orElse(null);
  }

}
