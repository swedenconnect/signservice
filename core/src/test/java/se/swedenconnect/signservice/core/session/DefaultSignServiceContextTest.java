/*
 * MIT License
 *
 * Copyright 2022 Sweden Connect
 */
package se.swedenconnect.signservice.core.session;

import org.apache.commons.lang3.SerializationUtils;
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
    context.put("Item3", new String[] {"A", "B", "C"});

    final DefaultSignServiceContext context2 = SerializationUtils.roundtrip(context);

    Assertions.assertEquals("ID1", context.getId());
    Assertions.assertEquals("Hejsan", context2.get("Item1"));
    Assertions.assertEquals(Integer.valueOf(17), context2.get("Item2"));
    Assertions.assertArrayEquals(new String[] {"A", "B", "C"}, context2.get("Item3"));
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
