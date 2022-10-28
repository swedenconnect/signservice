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
package se.swedenconnect.signservice.application;

import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;

public class DefaultSignServiceProcessingResult implements SignServiceProcessingResult {

  private final HttpRequestMessage httpRequestMessage;
  private final SignServiceContext context;

  public DefaultSignServiceProcessingResult(final SignServiceContext context, final HttpRequestMessage httpRequestMessage) {
    this.context = context;
    this.httpRequestMessage = httpRequestMessage;
  }

  @Override
  public SignServiceContext getSignServiceContext() {
    return this.context;
  }

  @Override
  public HttpRequestMessage getHttpRequestMessage() {
    return this.httpRequestMessage;
  }

}
