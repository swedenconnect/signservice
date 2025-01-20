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

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import jakarta.annotation.Nullable;

/**
 * The {@code HttpResponseAction} interface is used as a result object for SignService engines and handlers that process
 * user requests ({@link HttpUserRequest}).
 * <p>
 * The {@code HttpResponseAction} can represent three different types of responses:
 * </p>
 * <ul>
 * <li>The user's browser should be redirected to a given URL.</li>
 * <li>The user's browser should be posted to a given URL with a set of parameters.</li>
 * <li>A response message should be written (HTTP Status 200).</li>
 * </ul>
 * <b>Note:</b> A {@code HttpResponseAction} instance can only represent one of the above types.
 */
@JsonDeserialize(using = DefaultHttpResponseActionDeserializer.class)
public interface HttpResponseAction {

  /**
   * If the response action is that a HTTP redirect should be performed this method returns the
   * {@link HttpRedirectAction} telling where the user's browser should be directed.
   *
   * @return a HttpRedirectAction, or null if this is not a redirect action
   */
  @Nullable
  HttpRedirectAction getRedirect();

  /**
   * If the response action is that a HTTP POST should be performed this method returns the {@link HttpPostAction}
   * telling where the user's browser should be posted and with which parameters.
   *
   * @return a HttpPostAction, or null if this is not a post action
   */
  @Nullable
  HttpPostAction getPost();

  /**
   * If the response action is that the SignService should reply to a request by sending back a 200 status with a
   * response body this method return {@link HttpBodyAction} object that tells how the HTTP response should be
   * constructed (filled in).
   *
   * @return a HttpBodyAction, or null if this is not a response body action
   */
  @Nullable
  HttpBodyAction getBody();

}
