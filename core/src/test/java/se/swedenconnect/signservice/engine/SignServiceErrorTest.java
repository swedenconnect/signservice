/*
 * Copyright 2022-2024 Sweden Connect
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
package se.swedenconnect.signservice.engine;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for SignServiceError.
 */
public class SignServiceErrorTest {

  @Test
  public void testDefaultMsg() {
    final SignServiceError e = new SignServiceError(SignServiceErrorCode.REQUEST_INCORRECT);
    Assertions.assertEquals(SignServiceErrorCode.REQUEST_INCORRECT.getDefaultMessage(), e.getMessage());
    Assertions.assertNull(e.getDetailedMessage());
    Assertions.assertEquals(
        "error-code='REQUEST_INCORRECT', message='The sign request message is incorrect', detailed-message='null'",
        e.toString());
  }

  @Test
  public void testSpecificMsg() {
    final SignServiceError e = new SignServiceError(SignServiceErrorCode.REQUEST_INCORRECT, "Bad");
    Assertions.assertEquals("Bad", e.getMessage());
    Assertions.assertNull(e.getDetailedMessage());
    Assertions.assertEquals(
        "error-code='REQUEST_INCORRECT', message='Bad', detailed-message='null'",
        e.toString());
  }

  @Test
  public void testDetailedMsg() {
    final SignServiceError e = new SignServiceError(SignServiceErrorCode.REQUEST_INCORRECT, null, "detail");
    Assertions.assertEquals(SignServiceErrorCode.REQUEST_INCORRECT.getDefaultMessage(), e.getMessage());
    Assertions.assertEquals("detail", e.getDetailedMessage());
    Assertions.assertEquals(
        "error-code='REQUEST_INCORRECT', message='The sign request message is incorrect', detailed-message='detail'",
        e.toString());
  }

}
