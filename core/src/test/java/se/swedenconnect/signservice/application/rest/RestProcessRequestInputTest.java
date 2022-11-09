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
package se.swedenconnect.signservice.application.rest;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import se.swedenconnect.signservice.core.http.HttpUserRequest;

/**
 * Test cases for RestProcessRequestInput.
 */
public class RestProcessRequestInputTest {

  @Test
  public void test() {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);

    final RestProcessRequestInput input = new RestProcessRequestInput();
    input.setUserRequest(request);
    input.setContext("ctx");
    Assertions.assertNotNull(input.getUserRequest());
    Assertions.assertEquals("ctx", input.getContext());

    final RestProcessRequestInput input2 = new RestProcessRequestInput("ctx", request);
    Assertions.assertNotNull(input2.getUserRequest());
    Assertions.assertEquals("ctx", input2.getContext());
  }
}
