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
package se.swedenconnect.signservice.authn;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import se.swedenconnect.signservice.core.http.HttpRequestMessage;

/**
 * Test cases for AuthenticationResultChoice.
 */
public class AuthenticationResultChoiceTest {

  @Test
  public void testNull() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new AuthenticationResultChoice((HttpRequestMessage) null);
    });
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new AuthenticationResultChoice((AuthenticationResult) null);
    });
  }

  @Test
  public void testMsg() {
    final AuthenticationResultChoice choice = new AuthenticationResultChoice(Mockito.mock(HttpRequestMessage.class));
    Assertions.assertNotNull(choice.getHttpRequestMessage());
    Assertions.assertNotNull(choice.getFirst());
    Assertions.assertNull(choice.getAuthenticationResult());
    Assertions.assertNull(choice.getSecond());
  }

  @Test
  public void testResult() {

    final AuthenticationResultChoice choice = new AuthenticationResultChoice(Mockito.mock(AuthenticationResult.class));
    Assertions.assertNotNull(choice.getAuthenticationResult());
    Assertions.assertNotNull(choice.getSecond());
    Assertions.assertNull(choice.getHttpRequestMessage());
    Assertions.assertNull(choice.getFirst());
  }

}
