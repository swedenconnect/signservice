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
package se.swedenconnect.signservice.authn.impl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for SimpleAuthnContextIdentifier.
 */
public class SimpleAuthnContextIdentifierTest {

  @Test
  public void testNull() {
    Assertions.assertThrows(NullPointerException.class, () -> {
      new SimpleAuthnContextIdentifier(null);
    }, "identifier must not be null");
  }

  @Test
  public void testUsage() {
    SimpleAuthnContextIdentifier id = new SimpleAuthnContextIdentifier("http://id.elegnamnden.se/loa/1.0/loa3");
    Assertions.assertEquals("http://id.elegnamnden.se/loa/1.0/loa3", id.getIdentifier());
    Assertions.assertEquals("http://id.elegnamnden.se/loa/1.0/loa3", id.toString());
  }

}
