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
package se.swedenconnect.signservice.signature.impl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for DefaultAdESObject.
 */
public class DefaultAdESObjectTest {

  @Test
  public void testNull() {
    final DefaultAdESObject o = new DefaultAdESObject(null, null);
    Assertions.assertNull(o.getSignatureId());
    Assertions.assertNull(o.getObjectBytes());
    Assertions.assertEquals("signature-id='null', object-bytes=[0 bytes]", o.toString());
  }

  @Test
  public void testUsage() {
    final DefaultAdESObject o = new DefaultAdESObject("123", "bytes".getBytes());
    Assertions.assertEquals("123", o.getSignatureId());
    Assertions.assertArrayEquals("bytes".getBytes(), o.getObjectBytes());
    Assertions.assertEquals("signature-id='123', object-bytes=[5 bytes]", o.toString());
  }
}
