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
package se.swedenconnect.signservice.protocol.dss.jaxb;

import java.math.BigInteger;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Arrays;

import javax.xml.datatype.XMLGregorianCalendar;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import se.swedenconnect.schemas.saml_2_0.assertion.Attribute;
import se.swedenconnect.signservice.core.attribute.AttributeException;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.SamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.BooleanSamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.DateSamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.InstantSamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.IntegerSamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;

/**
 * Test cases for JaxbAttributeConverter.
 */
public class JaxbAttributeConverterTest {

  private static JaxbAttributeConverter converter = new JaxbAttributeConverter();

  @Test
  public void testNullParameter() throws Exception {
    Assertions.assertNull(converter.convert((Attribute) null));
    Assertions.assertNull(converter.convert((IdentityAttribute<?>) null));
  }

  @Test
  public void testToAttributeNotSaml() {
    final IdentityAttribute<?> attr = Mockito.mock(IdentityAttribute.class);
    Mockito.when(attr.getScheme()).thenReturn("OIDC");

    Assertions.assertThrows(AttributeException.class, () -> {
      converter.convert(attr);
    });
  }

  @Test
  public void testConvertAndBackString() throws AttributeException {
    final StringSamlIdentityAttribute attr = new StringSamlIdentityAttribute(
        "urn:oid:2.5.4.42", "givenName", Arrays.asList("Hans", "Martin"));

    final Attribute jaxb = converter.convert(attr);

    Assertions.assertEquals("urn:oid:2.5.4.42", jaxb.getName());
    Assertions.assertEquals("givenName", jaxb.getFriendlyName());
    Assertions.assertEquals(SamlIdentityAttribute.DEFAULT_NAME_FORMAT, jaxb.getNameFormat());
    Assertions.assertEquals("Hans", jaxb.getAttributeValues().get(0));
    Assertions.assertEquals("Martin", jaxb.getAttributeValues().get(1));

    final IdentityAttribute<?> genAttr = converter.convert(jaxb);

    Assertions.assertEquals(attr, genAttr);
  }

  @Test
  public void testConvertAndBackBoolean() throws AttributeException {
    final BooleanSamlIdentityAttribute attr = new BooleanSamlIdentityAttribute(
        "urn:oid:1.2.3.4", "test", Boolean.TRUE);

    final Attribute jaxb = converter.convert(attr);

    Assertions.assertEquals("urn:oid:1.2.3.4", jaxb.getName());
    Assertions.assertEquals("test", jaxb.getFriendlyName());
    Assertions.assertEquals(SamlIdentityAttribute.DEFAULT_NAME_FORMAT, jaxb.getNameFormat());
    Assertions.assertEquals(Boolean.TRUE, jaxb.getAttributeValues().get(0));

    final IdentityAttribute<?> genAttr = converter.convert(jaxb);

    Assertions.assertEquals(attr, genAttr);
  }

  @Test
  public void testConvertAndBackInteger() throws AttributeException {
    final IntegerSamlIdentityAttribute attr = new IntegerSamlIdentityAttribute(
        "urn:oid:1.2.3.4", "test", Integer.valueOf(17));

    final Attribute jaxb = converter.convert(attr);

    Assertions.assertEquals("urn:oid:1.2.3.4", jaxb.getName());
    Assertions.assertEquals("test", jaxb.getFriendlyName());
    Assertions.assertEquals(SamlIdentityAttribute.DEFAULT_NAME_FORMAT, jaxb.getNameFormat());
    Assertions.assertEquals(BigInteger.valueOf(17), jaxb.getAttributeValues().get(0));

    final IdentityAttribute<?> genAttr = converter.convert(jaxb);

    Assertions.assertEquals(attr, genAttr);
  }

  @Test
  public void testConvertAndBackDate() throws AttributeException {
    final DateSamlIdentityAttribute attr = new DateSamlIdentityAttribute(
        "urn:oid:1.2.3.4", "test", LocalDate.parse("2022-04-01"));

    final Attribute jaxb = converter.convert(attr);

    Assertions.assertEquals("urn:oid:1.2.3.4", jaxb.getName());
    Assertions.assertEquals("test", jaxb.getFriendlyName());
    Assertions.assertEquals(SamlIdentityAttribute.DEFAULT_NAME_FORMAT, jaxb.getNameFormat());
    Assertions.assertTrue(jaxb.getAttributeValues().get(0) instanceof XMLGregorianCalendar);
    final XMLGregorianCalendar cal = (XMLGregorianCalendar) jaxb.getAttributeValues().get(0);
    Assertions.assertEquals("date", cal.getXMLSchemaType().getLocalPart());
    Assertions.assertEquals("2022-04-01", cal.toXMLFormat());

    final IdentityAttribute<?> genAttr = converter.convert(jaxb);

    Assertions.assertEquals(attr, genAttr);
  }

  @Test
  public void testConvertAndBackInstant() throws AttributeException {
    final InstantSamlIdentityAttribute attr = new InstantSamlIdentityAttribute(
        "urn:oid:1.2.3.4", "test", Instant.parse("2021-12-03T10:15:30.00Z"));

    final Attribute jaxb = converter.convert(attr);

    Assertions.assertEquals("urn:oid:1.2.3.4", jaxb.getName());
    Assertions.assertEquals("test", jaxb.getFriendlyName());
    Assertions.assertEquals(SamlIdentityAttribute.DEFAULT_NAME_FORMAT, jaxb.getNameFormat());
    Assertions.assertTrue(jaxb.getAttributeValues().get(0) instanceof XMLGregorianCalendar);
    final XMLGregorianCalendar cal = (XMLGregorianCalendar) jaxb.getAttributeValues().get(0);
    Assertions.assertEquals("dateTime", cal.getXMLSchemaType().getLocalPart());
    Assertions.assertTrue(cal.toXMLFormat().startsWith("2021-12-03T"));

    final IdentityAttribute<?> genAttr = converter.convert(jaxb);

    Assertions.assertEquals(attr, genAttr);
  }

  @Test
  public void testDifferentTypes() {
    final Attribute jaxb = new Attribute();
    jaxb.setName("urn:oid:2.5.4.42");
    jaxb.setNameFormat(SamlIdentityAttribute.DEFAULT_NAME_FORMAT);
    jaxb.getAttributeValues().add(new String("Kalle"));
    jaxb.getAttributeValues().add(Boolean.TRUE);

    Assertions.assertThrows(AttributeException.class, () -> {
      converter.convert(jaxb);
    }, "Multi-valued SAML attribute has different value types - this is not supported");
  }

  @Test
  public void testMissingName() {
    final Attribute jaxb = new Attribute();
    jaxb.setNameFormat(SamlIdentityAttribute.DEFAULT_NAME_FORMAT);
    jaxb.getAttributeValues().add(new String("Kalle"));

    Assertions.assertThrows(AttributeException.class, () -> {
      converter.convert(jaxb);
    }, "Invalid SAML attribute - missing name");
  }

  @Test
  public void testMissingValues() {
    final Attribute jaxb = new Attribute();
    jaxb.setName("urn:oid:2.5.4.42");
    jaxb.setNameFormat(SamlIdentityAttribute.DEFAULT_NAME_FORMAT);

    Assertions.assertThrows(AttributeException.class, () -> {
      converter.convert(jaxb);
    }, "Invalid SAML attribute - missing value(s)");
  }

  // TODO: More here

}
