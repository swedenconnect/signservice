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
package se.swedenconnect.signservice.core.http;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * An interface that is extended by SignService handlers that supports returning HTTP resources.
 */
public interface HttpResourceProvider {

  /**
   * Gets an HTTP resource. The returned resource will be written to the supplied {@link HttpServletResponse}, but it
   * will <b>not</b> commit the response. This is the responsibility of the caller.
   *
   * @param httpRequest the HTTP request
   * @param httpResponse the HTTP response
   * @throws IOException for processing errors
   */
  void getResource(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse) throws IOException;

  /**
   * Given the request the method determines whether it can supply a resource (via
   * {@link #getResource(HttpServletRequest, HttpServletResponse)}).
   *
   * @param httpRequest the HTTP request
   * @return true if the handler can process the request and provide an HTTP resource and false otherwise
   */
  boolean supports(final HttpServletRequest httpRequest);

}
