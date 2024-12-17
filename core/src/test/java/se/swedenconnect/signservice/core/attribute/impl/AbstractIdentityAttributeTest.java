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
package se.swedenconnect.signservice.core.attribute.impl;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for AbstractIdentityAttribute.
 */
public class AbstractIdentityAttributeTest {

  private final static String claim = "https://claims.oidc.se/1.0/personalNumber";
  private final static String friendly = "personalNumber";

  @Test
  public void testCtorNulls() throws Exception {
    Assertions.assertThrows(NullPointerException.class, () -> {
      new Attr(null, claim, null, "1");
    });
    Assertions.assertThrows(NullPointerException.class, () -> {
      new Attr("OIDC", null, friendly, "1");
    });
    Assertions.assertThrows(NullPointerException.class, () -> {
      new Attr("OIDC", claim, friendly, (String) null);
    });
    Assertions.assertThrows(NullPointerException.class, () -> {
      new Attr("OIDC", claim, friendly, (List<String>) null);
    });
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new Attr("OIDC", claim, friendly, Collections.emptyList());
    });
  }

  @Test
  public void testUsageSingle() {
    final Attr attr = new Attr("OIDC", claim, friendly, "190001011809");
    Assertions.assertEquals("OIDC", attr.getScheme());
    Assertions.assertEquals(claim, attr.getIdentifier());
    Assertions.assertEquals(friendly, attr.getFriendlyName());
    Assertions.assertEquals("190001011809", attr.getValue());
    Assertions.assertEquals(Arrays.asList("190001011809"), attr.getValues());
    Assertions.assertFalse(attr.isMultiValued());
    Assertions.assertEquals(String.format("[OIDC] %s (%s): 190001011809", claim, friendly), attr.toString());
  }

  @Test
  public void testUsageMulti() {
    final Attr attr = new Attr("OIDC", claim, null, Arrays.asList("190001011809", "9999"));
    Assertions.assertEquals("OIDC", attr.getScheme());
    Assertions.assertEquals(claim, attr.getIdentifier());
    Assertions.assertNull(attr.getFriendlyName());
    Assertions.assertEquals("190001011809", attr.getValue());
    Assertions.assertEquals(Arrays.asList("190001011809", "9999"), attr.getValues());
    Assertions.assertTrue(attr.isMultiValued());
    Assertions.assertEquals(String.format("[OIDC] %s: [190001011809, 9999]", claim), attr.toString());
  }

  public static class Attr extends AbstractIdentityAttribute<String> {

    private static final long serialVersionUID = -2571749904724075372L;

    public Attr(final String scheme, final String identifier, final String friendlyName, final String value) {
      super(scheme, identifier, friendlyName, value);
    }

    public Attr(final String scheme, final String identifier, final String friendlyName, final List<String> values) {
      super(scheme, identifier, friendlyName, values);
    }

    @Override
    public Class<String> getAttributeValueType() {
      return String.class;
    }

  }

}
