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
package se.swedenconnect.signservice.context;

import java.time.Instant;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for DefaultSignServiceContext.
 */
public class DefaultSignServiceContextTest {

  @Test
  public void testSerializeDeserialize() throws Exception {
    final DefaultSignServiceContext context = new DefaultSignServiceContext("ID1");
    context.put("Item1", new String("Hejsan"));
    context.put("Item2", Integer.valueOf(17));
    context.put("Item3", new String[] { "A", "B", "C" });

    final String encoding = context.serialize();

    final DefaultSignServiceContext context2 = DefaultSignServiceContext.deserialize(encoding);

    Assertions.assertEquals("ID1", context2.getId());
    Assertions.assertEquals("Hejsan", context2.get("Item1"));
    Assertions.assertEquals(Integer.valueOf(17), context2.get("Item2"));
    Assertions.assertArrayEquals(new String[] { "A", "B", "C" }, context2.get("Item3"));

    Assertions.assertNull(context2.get("Item4", Instant.class));
  }

  @Test
  public void testClassCastException() throws Exception {
    final DefaultSignServiceContext context = new DefaultSignServiceContext("ID1");
    context.put("Item1", new String("Hejsan"));

    Assertions.assertThrows(ClassCastException.class, () -> {
      context.get("Item1", Integer.class);
    });
  }

  @Test
  public void testRemoved() throws Exception {
    final DefaultSignServiceContext context = new DefaultSignServiceContext("ID1");
    context.put("Item1", new String("Hejsan"));

    Assertions.assertEquals("Hejsan", context.get("Item1"));

    context.remove("Item1");

    Assertions.assertNull(context.get("Item1"));
  }

}
