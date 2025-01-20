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
package se.swedenconnect.signservice.authn.saml;

import java.time.Instant;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.opensaml.saml2.attribute.AttributeBuilder;
import se.swedenconnect.opensaml.saml2.attribute.AttributeUtils;
import se.swedenconnect.signservice.core.attribute.AttributeException;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.SamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.BooleanSamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.DateSamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.InstantSamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.IntegerSamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;

/**
 * Test cases for OpenSamlAttributeConverter.
 */
public class OpenSamlAttributeConverterTest extends OpenSamlTestBase {

  private static OpenSamlAttributeConverter converter = new OpenSamlAttributeConverter();

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

    final Attribute a = converter.convert(attr);

    Assertions.assertEquals("urn:oid:2.5.4.42", a.getName());
    Assertions.assertEquals("givenName", a.getFriendlyName());
    Assertions.assertEquals(SamlIdentityAttribute.DEFAULT_NAME_FORMAT, a.getNameFormat());
    final List<String> values = AttributeUtils.getAttributeStringValues(a);
    Assertions.assertEquals("Hans", values.get(0));
    Assertions.assertEquals("Martin", values.get(1));

    final IdentityAttribute<?> genAttr = converter.convert(a);

    Assertions.assertEquals(attr, genAttr);
  }

  @Test
  public void testConvertAndBackBoolean() throws AttributeException {
    final BooleanSamlIdentityAttribute attr = new BooleanSamlIdentityAttribute(
        "urn:oid:1.2.3.4", "test", Boolean.TRUE);

    final Attribute a = converter.convert(attr);

    Assertions.assertEquals("urn:oid:1.2.3.4", a.getName());
    Assertions.assertEquals("test", a.getFriendlyName());
    Assertions.assertEquals(SamlIdentityAttribute.DEFAULT_NAME_FORMAT, a.getNameFormat());
    Assertions.assertEquals(Boolean.TRUE, ((XSBoolean) a.getAttributeValues().get(0)).getValue().getValue());

    final IdentityAttribute<?> genAttr = converter.convert(a);

    Assertions.assertEquals(attr, genAttr);
  }

  @Test
  public void testConvertAndBackInteger() throws AttributeException {
    final IntegerSamlIdentityAttribute attr = new IntegerSamlIdentityAttribute(
        "urn:oid:1.2.3.4", "test", Integer.valueOf(17));

    final Attribute a = converter.convert(attr);

    Assertions.assertEquals("urn:oid:1.2.3.4", a.getName());
    Assertions.assertEquals("test", a.getFriendlyName());
    Assertions.assertEquals(SamlIdentityAttribute.DEFAULT_NAME_FORMAT, a.getNameFormat());
    Assertions.assertEquals(Integer.valueOf(17), ((XSInteger) a.getAttributeValues().get(0)).getValue());

    final IdentityAttribute<?> genAttr = converter.convert(a);

    Assertions.assertEquals(attr, genAttr);
  }

  @Test
  public void testConvertDate() throws AttributeException {
    final DateSamlIdentityAttribute attr = new DateSamlIdentityAttribute(
        "urn:oid:1.2.3.4", "test", LocalDate.parse("2022-04-01"));
    final StringSamlIdentityAttribute attr2 = new StringSamlIdentityAttribute(
        "urn:oid:1.2.3.4", "test", "2022-04-01");

    final Attribute a = converter.convert(attr);

    Assertions.assertEquals("urn:oid:1.2.3.4", a.getName());
    Assertions.assertEquals("test", a.getFriendlyName());
    Assertions.assertEquals(SamlIdentityAttribute.DEFAULT_NAME_FORMAT, a.getNameFormat());
    Assertions.assertEquals("2022-04-01", ((XSString) a.getAttributeValues().get(0)).getValue());

    final IdentityAttribute<?> genAttr = converter.convert(a);

    Assertions.assertEquals(attr2, genAttr);
  }

  @Test
  public void testConvertAndBackInstant() throws AttributeException {
    final Instant dateTime = Instant.parse("2021-12-03T10:15:30.00Z");
    final InstantSamlIdentityAttribute attr = new InstantSamlIdentityAttribute(
        "urn:oid:1.2.3.4", "test", dateTime);

    final Attribute a = converter.convert(attr);

    Assertions.assertEquals("urn:oid:1.2.3.4", a.getName());
    Assertions.assertEquals("test", a.getFriendlyName());
    Assertions.assertEquals(SamlIdentityAttribute.DEFAULT_NAME_FORMAT, a.getNameFormat());
    Assertions.assertEquals(dateTime, ((XSDateTime) a.getAttributeValues().get(0)).getValue());

    final IdentityAttribute<?> genAttr = converter.convert(a);

    Assertions.assertEquals(attr, genAttr);
  }

  @Test
  public void testDifferentTypes() {
    final XSString stringValue = AttributeBuilder.createValueObject(XSString.TYPE_NAME, XSString.class);
    stringValue.setValue("Kalle");
    final XSBoolean booleanValue = AttributeBuilder.createValueObject(XSBoolean.TYPE_NAME, XSBoolean.class);
    booleanValue.setValue(new XSBooleanValue(Boolean.TRUE, false));

    final Attribute a = AttributeBuilder.builder("urn:oid:2.5.4.42")
        .nameFormat(SamlIdentityAttribute.DEFAULT_NAME_FORMAT)
        .value(stringValue)
        .value(booleanValue)
        .build();

    Assertions.assertThrows(AttributeException.class, () -> {
      converter.convert(a);
    }, "Multi-valued SAML attribute has different value types - this is not supported");
  }

  @Test
  public void testMissingName() {
    final Attribute a = (Attribute) XMLObjectSupport.buildXMLObject(Attribute.DEFAULT_ELEMENT_NAME);
    a.setNameFormat(SamlIdentityAttribute.DEFAULT_NAME_FORMAT);

    final XSString stringValue = AttributeBuilder.createValueObject(XSString.TYPE_NAME, XSString.class);
    stringValue.setValue("Kalle");
    a.getAttributeValues().add(stringValue);

    Assertions.assertThrows(AttributeException.class, () -> {
      converter.convert(a);
    }, "Invalid SAML attribute - missing name");
  }

  @Test
  public void testMissingValues() {
    final Attribute a = AttributeBuilder.builder("urn:oid:2.5.4.42")
        .nameFormat(SamlIdentityAttribute.DEFAULT_NAME_FORMAT)
        .build();

    Assertions.assertThrows(AttributeException.class, () -> {
      converter.convert(a);
    }, "Invalid SAML attribute - missing value(s)");
  }

}
