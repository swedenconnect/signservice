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
package se.swedenconnect.signservice.protocol.msg.impl;

import java.time.Instant;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for DefaultMessageConditions.
 */
public class DefaultMessageConditionsTest {

  @Test
  public void testRangeCheck() {

    final Instant notBefore = Instant.now().minusSeconds(120);
    final Instant notAfter = Instant.now().plusSeconds(120);

    DefaultMessageConditions conditions = new DefaultMessageConditions(notBefore, notAfter);

    Assertions.assertTrue(conditions.isWithinRange(Instant.now()));
    Assertions.assertFalse(conditions.isWithinRange(Instant.now().minusSeconds(300)));
    Assertions.assertFalse(conditions.isWithinRange(Instant.now().plusSeconds(300)));
    Assertions.assertFalse(conditions.isWithinRange(null));

    conditions = new DefaultMessageConditions(null, notAfter);
    Assertions.assertTrue(conditions.isWithinRange(Instant.now()));
    Assertions.assertTrue(conditions.isWithinRange(Instant.now().minusSeconds(300)));
    Assertions.assertFalse(conditions.isWithinRange(Instant.now().plusSeconds(300)));

    conditions = new DefaultMessageConditions(notBefore, null);
    Assertions.assertTrue(conditions.isWithinRange(Instant.now()));
    Assertions.assertFalse(conditions.isWithinRange(Instant.now().minusSeconds(300)));
    Assertions.assertTrue(conditions.isWithinRange(Instant.now().plusSeconds(300)));

    conditions = new DefaultMessageConditions(null, null);
    Assertions.assertTrue(conditions.isWithinRange(Instant.now()));
    Assertions.assertTrue(conditions.isWithinRange(Instant.now().minusSeconds(300)));
    Assertions.assertTrue(conditions.isWithinRange(Instant.now().plusSeconds(300)));
  }

  @Test
  public void testInvalidConstructor() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new DefaultMessageConditions(Instant.now(), Instant.now().minusSeconds(10));
    });
  }

  @Test
  public void testToString() {
    final Instant notBefore = Instant.parse("2022-03-31T10:15:30.00Z");
    final Instant notAfter = Instant.parse("2022-03-31T10:15:35.00Z");

    final DefaultMessageConditions conditions = new DefaultMessageConditions(notBefore, notAfter);
    Assertions.assertEquals("not-before='2022-03-31T10:15:30Z', not-after='2022-03-31T10:15:35Z'", conditions.toString());
  }

}
