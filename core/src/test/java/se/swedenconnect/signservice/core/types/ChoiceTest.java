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
package se.swedenconnect.signservice.core.types;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for Choice.
 */
public class ChoiceTest {

  @Test
  public void testNullPars() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new Choice<String, String>(null, null);
    });
  }

  @Test
  public void testBothParsSet() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new Choice<String, String>("A", "B");
    });
  }

  @Test
  public void testFirstSet() {
    final Choice<String, String> c = new Choice<>("A", null);
    Assertions.assertEquals("A", c.getFirst());
    Assertions.assertNull(c.getSecond());
  }

  @Test
  public void testSecondSet() {
    final Choice<String, String> c = new Choice<>(null, "B");
    Assertions.assertNull(c.getFirst());
    Assertions.assertEquals("B", c.getSecond());
  }

}
