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
package se.swedenconnect.signservice.protocol.dss.jaxb;

import java.math.BigInteger;
import java.time.Instant;
import java.time.LocalDate;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import se.swedenconnect.schemas.saml_2_0.assertion.Attribute;
import se.swedenconnect.signservice.core.attribute.AttributeConverter;
import se.swedenconnect.signservice.core.attribute.AttributeException;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.SamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.AbstractSamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.BooleanSamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.DateSamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.InstantSamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.IntegerSamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;

/**
 * An {@link AttributeConverter} for the JAXB representation of a SAML {@link Attribute}.
 */
public class JaxbAttributeConverter implements AttributeConverter<Attribute> {

  /** {@inheritDoc} */
  @Override
  public Attribute convert(final IdentityAttribute<?> attribute) throws AttributeException {
    if (attribute == null) {
      return null;
    }
    if (!"SAML".equals(attribute.getScheme())) {
      throw new AttributeException("Unsupported attribute type - " + attribute.getScheme());
    }
    final Attribute jaxbAttribute = new Attribute();
    jaxbAttribute.setName(attribute.getIdentifier());
    jaxbAttribute.setFriendlyName(attribute.getFriendlyName());
    if (attribute instanceof SamlIdentityAttribute<?>) {
      jaxbAttribute.setNameFormat(((SamlIdentityAttribute<?>) attribute).getNameFormat());
    }
    for (final Object v : attribute.getValues()) {
      // Make some conversions (where needed) ...
      if (Integer.class.isInstance(v)) {
        jaxbAttribute.getAttributeValues().add(BigInteger.valueOf(Integer.class.cast(v).longValue()));
      }
      else if (LocalDate.class.isInstance(v)) {
        try {
          jaxbAttribute.getAttributeValues().add(
              DatatypeFactory.newInstance().newXMLGregorianCalendar(LocalDate.class.cast(v).toString()));
        }
        catch (final DatatypeConfigurationException e) {
          throw new AttributeException("Failed to convert date", e);
        }
      }
      else if (Instant.class.isInstance(v)) {
        final GregorianCalendar calendar = new GregorianCalendar();
        calendar.setTimeInMillis(Instant.class.cast(v).toEpochMilli());
        try {
          jaxbAttribute.getAttributeValues().add(
              DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar));
        }
        catch (final DatatypeConfigurationException e) {
          throw new AttributeException("Failed to convert dateTime", e);
        }
      }
      else {
        jaxbAttribute.getAttributeValues().add(v);
      }
    }

    return jaxbAttribute;
  }

  /** {@inheritDoc} */
  @Override
  public IdentityAttribute<?> convert(final Attribute attribute) throws AttributeException {
    if (attribute == null) {
      return null;
    }
    final String attributeName = Optional.ofNullable(attribute.getName())
        .orElseThrow(() -> new AttributeException("Invalid SAML attribute - missing name"));
    final String friendlyName = attribute.getFriendlyName();
    if (!attribute.isSetAttributeValues()) {
      throw new AttributeException("Invalid SAML attribute - missing value(s)");
    }
    // Assert that all values have the same type and return this type.
    final Class<?> valueType = processValueType(attribute.getAttributeValues());
    AbstractSamlIdentityAttribute<?> genericAttribute;
    if (String.class.isAssignableFrom(valueType)) {
      genericAttribute = new StringSamlIdentityAttribute(attributeName, friendlyName,
          attribute.getAttributeValues().stream()
              .map(String.class::cast)
              .collect(Collectors.toList()));
    }
    else if (Boolean.class.isAssignableFrom(valueType)) {
      genericAttribute = new BooleanSamlIdentityAttribute(attributeName, friendlyName,
          attribute.getAttributeValues().stream()
              .map(Boolean.class::cast)
              .collect(Collectors.toList()));
    }
    else if (BigInteger.class.isAssignableFrom(valueType)) {
      genericAttribute = new IntegerSamlIdentityAttribute(attributeName, friendlyName,
          attribute.getAttributeValues().stream()
              .map(BigInteger.class::cast)
              .map(BigInteger::intValue)
              .collect(Collectors.toList()));
    }
    else if (XMLGregorianCalendar.class.isAssignableFrom(valueType)) {
      // date or dateTime?
      final XMLGregorianCalendar t = XMLGregorianCalendar.class.cast(attribute.getAttributeValues().get(0));
      if ("date".equals(t.getXMLSchemaType().getLocalPart())) {
        genericAttribute = new DateSamlIdentityAttribute(attributeName, friendlyName,
            attribute.getAttributeValues().stream()
                .map(XMLGregorianCalendar.class::cast)
                .map(x -> LocalDate.of(x.getYear(), x.getMonth(), x.getDay()))
                .collect(Collectors.toList()));
      }
      else { // dateTime
        genericAttribute = new InstantSamlIdentityAttribute(attributeName, friendlyName,
            attribute.getAttributeValues().stream()
                .map(XMLGregorianCalendar.class::cast)
                .map(XMLGregorianCalendar::toGregorianCalendar)
                .map(GregorianCalendar::toInstant)
                .collect(Collectors.toList()));
      }
    }
    else {
      // Assume String ...
      genericAttribute = new StringSamlIdentityAttribute(attributeName, friendlyName,
          attribute.getAttributeValues().stream()
              .map(Object::toString)
              .collect(Collectors.toList()));
    }

    genericAttribute.setNameFormat(attribute.getNameFormat());

    return genericAttribute;
  }

  /**
   * Checks that an attribute's values all are of the same type
   *
   * @param values the values to check
   * @return the value type
   * @throws AttributeException if different types appear
   */
  private static Class<?> processValueType(final List<Object> values) throws AttributeException {
    final Iterator<Object> i = values.iterator();
    final Class<?> type = i.next().getClass();
    while (i.hasNext()) {
      if (!type.isInstance(i.next())) {
        throw new AttributeException("Multi-valued SAML attribute has different value types - this is not supported");
      }
    }
    return type;
  }

}
