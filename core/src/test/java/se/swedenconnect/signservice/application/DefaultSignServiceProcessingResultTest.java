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

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.http.HttpResponseAction;

/**
 * Test cases for DefaultSignServiceProcessingResult.
 */
public class DefaultSignServiceProcessingResultTest {

  @Test
  public void test() {
    assertThatThrownBy(() -> {
      new DefaultSignServiceProcessingResult(null, null);
    }).isInstanceOf(NullPointerException.class)
        .hasMessage("responseAction must not be null");

    final HttpResponseAction action = Mockito.mock(HttpResponseAction.class);
    final DefaultSignServiceProcessingResult r1 = new DefaultSignServiceProcessingResult(null, action);
    Assertions.assertNotNull(r1.getResponseAction());
    Assertions.assertNull(r1.getSignServiceContext());

    final SignServiceContext context = Mockito.mock(SignServiceContext.class);
    final DefaultSignServiceProcessingResult r2 = new DefaultSignServiceProcessingResult(context, action);
    Assertions.assertNotNull(r2.getResponseAction());
    Assertions.assertNotNull(r2.getSignServiceContext());

  }

}
