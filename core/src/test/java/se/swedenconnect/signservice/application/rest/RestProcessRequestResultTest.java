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
package se.swedenconnect.signservice.application.rest;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import se.swedenconnect.signservice.application.SignServiceProcessingResult;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.http.HttpResponseAction;

/**
 * Test cases for RestProcessRequestResult.
 */
public class RestProcessRequestResultTest {

  @Test
  public void test() {
    final HttpResponseAction action = Mockito.mock(HttpResponseAction.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);
    Mockito.when(context.serialize()).thenReturn("ctx");

    final RestProcessRequestResult result = new RestProcessRequestResult();
    result.setContext("ctx");
    result.setResponseAction(action);
    Assertions.assertEquals("ctx", result.getContext());
    Assertions.assertNotNull(result.getResponseAction());

    final SignServiceProcessingResult presult = Mockito.mock(SignServiceProcessingResult.class);
    Mockito.when(presult.getResponseAction()).thenReturn(null);
    Mockito.when(presult.getSignServiceContext()).thenReturn(null);

    assertThatThrownBy(() -> {
      new RestProcessRequestResult(presult);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("No response action present");

    Mockito.when(presult.getResponseAction()).thenReturn(action);

    final RestProcessRequestResult result2 = new RestProcessRequestResult(presult);
    Assertions.assertNull(result2.getContext());
    Assertions.assertNotNull(result2.getResponseAction());

    Mockito.when(presult.getSignServiceContext()).thenReturn(context);
    final RestProcessRequestResult result3 = new RestProcessRequestResult(presult);
    Assertions.assertEquals("ctx", result3.getContext());
    Assertions.assertNotNull(result3.getResponseAction());
  }
}
