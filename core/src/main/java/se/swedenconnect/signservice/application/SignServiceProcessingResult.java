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
package se.swedenconnect.signservice.application;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.http.HttpResponseAction;

/**
 * An interface representing the result from a call to the SignService engine manager.
 */
public interface SignServiceProcessingResult {

  /**
   * Gets the SignService context (state). It is the responsibility of the application, or SignService frontend, to save
   * this context object in the user's HTTP session so that it can be supplied in the next call to the SignService
   * engine manager.
   * <p>
   * If {@code null} it means that the signature operation has completed and the application, or SignService frontend,
   * <b>MUST</b> remove the SignService context from the user's HTTP session.
   * </p>
   *
   * @return a SignService context, or null if the signature operation has completed
   */
  @Nullable
  SignServiceContext getSignServiceContext();

  /**
   * Depending on the type of request processed the SignService engine manager can respond with one of the following
   * types of responses:
   * <ul>
   * <li>The user's browser should be redirected to a given URL.</li>
   * <li>The user's browser should be posted to a given URL with a set of parameters.</li>
   * <li>A response message should be written (HTTP Status 200).</li>
   * </ul>
   * This method returns a {@link HttpResponseAction} that tells how the caller (application/frontend) should respond to
   * the request that it fed to the SignService engine manager.
   *
   * @return a HttpResponseAction
   */
  @Nonnull
  HttpResponseAction getResponseAction();

}
