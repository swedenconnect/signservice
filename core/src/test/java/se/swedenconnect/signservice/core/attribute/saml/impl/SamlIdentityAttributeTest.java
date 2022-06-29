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
package se.swedenconnect.signservice.core.attribute.saml.impl;

import java.time.Instant;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.core.attribute.saml.SamlIdentityAttribute;

/**
 * Test cases for SamlIdentityAttribute classes.
 */
public class SamlIdentityAttributeTest {

  @Test
  public void testNullCtor() {
    Assertions.assertThrows(NullPointerException.class, () -> {
      new StringSamlIdentityAttribute(null, "friendly", "value");
    });
    Assertions.assertThrows(NullPointerException.class, () -> {
      new StringSamlIdentityAttribute("id", null, (String) null);
    });
    Assertions.assertThrows(NullPointerException.class, () -> {
      new StringSamlIdentityAttribute("id", (String) null, (List<String>) null);
    });
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new StringSamlIdentityAttribute("id", null, Collections.emptyList());
    });
  }

  @Test
  public void testSamlIdentityAttributeDefaults() {
    final SamlIdentityAttribute<String> a = new SamlIdentityAttribute<>() {

      @Override
      public List<String> getValues() {
        return null;
      }

      @Override
      public String getValue() {
        return null;
      }

      @Override
      public boolean isMultiValued() {
        return false;
      }

      @Override
      public Class<String> getAttributeValueType() {
        return null;
      }

      @Override
      public String getIdentifier() {
        return "id";
      }

      @Override
      public String getFriendlyName() {
        return null;
      }

      @Override
      public String getNameFormat() {
        return null;
      }
    };

    Assertions.assertEquals("SAML", a.getScheme());
    Assertions.assertEquals("id", a.getName());
  }

  @Test
  public void testUsageString() {
    StringSamlIdentityAttribute a = new StringSamlIdentityAttribute("id", "friendly", "value");
    a.setNameFormat("otherNameFormat");
    Assertions.assertEquals("SAML", a.getScheme());
    Assertions.assertEquals(String.class, a.getAttributeValueType());
    Assertions.assertEquals("id", a.getIdentifier());
    Assertions.assertEquals("id", a.getName());
    Assertions.assertEquals("friendly", a.getFriendlyName());
    Assertions.assertEquals("value", a.getValue());
    Assertions.assertEquals(Arrays.asList("value"), a.getValues());
    Assertions.assertFalse(a.isMultiValued());
    Assertions.assertEquals("otherNameFormat", a.getNameFormat());
    Assertions.assertEquals("[SAML] id (friendly): value", a.toString());

    a = new StringSamlIdentityAttribute("id", null, Arrays.asList("value1", "value2"));
    Assertions.assertEquals(String.class, a.getAttributeValueType());
    Assertions.assertEquals("id", a.getIdentifier());
    Assertions.assertNull(a.getFriendlyName());
    Assertions.assertEquals("value1", a.getValue());
    Assertions.assertEquals(Arrays.asList("value1", "value2"), a.getValues());
    Assertions.assertTrue(a.isMultiValued());
    Assertions.assertEquals(SamlIdentityAttribute.DEFAULT_NAME_FORMAT, a.getNameFormat());
    Assertions.assertEquals("[SAML] id: [value1, value2]", a.toString());
  }

  @Test
  public void testUsageBoolean() {
    BooleanSamlIdentityAttribute a = new BooleanSamlIdentityAttribute("id", "friendly", true);
    Assertions.assertEquals(Boolean.class, a.getAttributeValueType());
    Assertions.assertEquals("id", a.getIdentifier());
    Assertions.assertEquals("friendly", a.getFriendlyName());
    Assertions.assertEquals(Boolean.TRUE, a.getValue());
    Assertions.assertEquals(Arrays.asList(Boolean.TRUE), a.getValues());
    Assertions.assertFalse(a.isMultiValued());
    Assertions.assertEquals("[SAML] id (friendly): true", a.toString());

    a = new BooleanSamlIdentityAttribute("id", null, Arrays.asList(Boolean.TRUE, Boolean.FALSE));
    Assertions.assertEquals(Boolean.TRUE, a.getValue());
    Assertions.assertEquals(Arrays.asList(Boolean.TRUE, Boolean.FALSE), a.getValues());
    Assertions.assertTrue(a.isMultiValued());
    Assertions.assertEquals("[SAML] id: [true, false]", a.toString());
  }

  @Test
  public void testUsageInteger() {
    IntegerSamlIdentityAttribute a = new IntegerSamlIdentityAttribute("id", "friendly", 17);
    Assertions.assertEquals(Integer.class, a.getAttributeValueType());
    Assertions.assertEquals("id", a.getIdentifier());
    Assertions.assertEquals("friendly", a.getFriendlyName());
    Assertions.assertEquals(Integer.valueOf(17), a.getValue());
    Assertions.assertEquals(Arrays.asList(Integer.valueOf(17)), a.getValues());
    Assertions.assertFalse(a.isMultiValued());
    Assertions.assertEquals("[SAML] id (friendly): 17", a.toString());

    a = new IntegerSamlIdentityAttribute("id", null, Arrays.asList(Integer.valueOf(17), Integer.valueOf(25)));
    Assertions.assertEquals(Arrays.asList(Integer.valueOf(17), Integer.valueOf(25)), a.getValues());
    Assertions.assertTrue(a.isMultiValued());
    Assertions.assertEquals("[SAML] id: [17, 25]", a.toString());
  }

  @Test
  public void testUsageInstant() {
    final Instant i1 = Instant.parse("2022-03-31T10:15:30Z");
    InstantSamlIdentityAttribute a = new InstantSamlIdentityAttribute("id", "friendly", i1);
    Assertions.assertEquals(Instant.class, a.getAttributeValueType());
    Assertions.assertEquals("id", a.getIdentifier());
    Assertions.assertEquals("friendly", a.getFriendlyName());
    Assertions.assertEquals(i1, a.getValue());
    Assertions.assertEquals(Arrays.asList(i1), a.getValues());
    Assertions.assertFalse(a.isMultiValued());
    Assertions.assertEquals("[SAML] id (friendly): 2022-03-31T10:15:30Z", a.toString());

    final Instant i2 = Instant.parse("2022-04-01T10:15:30Z");
    a = new InstantSamlIdentityAttribute("id", null, Arrays.asList(i1, i2));
    Assertions.assertEquals(Arrays.asList(i1, i2), a.getValues());
    Assertions.assertTrue(a.isMultiValued());
    Assertions.assertEquals("[SAML] id: [2022-03-31T10:15:30Z, 2022-04-01T10:15:30Z]", a.toString());
  }

  @Test
  public void testUsageDate() {
    final LocalDate i1 = LocalDate.parse("2022-03-31");
    DateSamlIdentityAttribute a = new DateSamlIdentityAttribute("id", "friendly", i1);
    Assertions.assertEquals(LocalDate.class, a.getAttributeValueType());
    Assertions.assertEquals("id", a.getIdentifier());
    Assertions.assertEquals("friendly", a.getFriendlyName());
    Assertions.assertEquals(i1, a.getValue());
    Assertions.assertEquals(Arrays.asList(i1), a.getValues());
    Assertions.assertFalse(a.isMultiValued());
    Assertions.assertEquals("[SAML] id (friendly): 2022-03-31", a.toString());

    final LocalDate i2 = LocalDate.parse("2022-04-01");
    a = new DateSamlIdentityAttribute("id", null, Arrays.asList(i1, i2));
    Assertions.assertEquals(Arrays.asList(i1, i2), a.getValues());
    Assertions.assertTrue(a.isMultiValued());
    Assertions.assertEquals("[SAML] id: [2022-03-31, 2022-04-01]", a.toString());
  }

}
