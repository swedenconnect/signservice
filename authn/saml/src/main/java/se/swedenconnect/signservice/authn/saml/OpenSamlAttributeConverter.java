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
package se.swedenconnect.signservice.authn.saml;

import java.time.Instant;
import java.time.LocalDate;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.opensaml.saml2.attribute.AttributeBuilder;
import se.swedenconnect.opensaml.saml2.attribute.AttributeUtils;
import se.swedenconnect.signservice.core.attribute.AttributeConverter;
import se.swedenconnect.signservice.core.attribute.AttributeException;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.SamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.AbstractSamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.BooleanSamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.InstantSamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.IntegerSamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;

/**
 * An {@link AttributeConverter} for the OpenSAML representation of a SAML {@link Attribute}.
 */
public class OpenSamlAttributeConverter implements AttributeConverter<Attribute> {

  /** {@inheritDoc} */
  @Override
  public Attribute convert(final IdentityAttribute<?> attribute) throws AttributeException {
    if (attribute == null) {
      return null;
    }
    if (!"SAML".equals(attribute.getScheme())) {
      throw new AttributeException("Unsupported attribute type - " + attribute.getScheme());
    }
    final AttributeBuilder builder = AttributeBuilder.builder(attribute.getIdentifier());
    builder.friendlyName(attribute.getFriendlyName());
    if (attribute instanceof SamlIdentityAttribute<?>) {
      builder.nameFormat(((SamlIdentityAttribute<?>) attribute).getNameFormat());
    }
    for (final Object v : attribute.getValues()) {
      if (String.class.isInstance(v)) {
        builder.value((String) v);
      }
      else if (Integer.class.isInstance(v)) {
        final XSInteger o = AttributeBuilder.createValueObject(XSInteger.TYPE_NAME, XSInteger.class);
        o.setValue((Integer) v);
        builder.value(o);
      }
      else if (Boolean.class.isInstance(v)) {
        final XSBoolean o = AttributeBuilder.createValueObject(XSBoolean.TYPE_NAME, XSBoolean.class);
        o.setValue(new XSBooleanValue((Boolean) v, false));
        builder.value(o);
      }
      else if (LocalDate.class.isInstance(v)) {
        // OpenSAML doesn't support xs:date, so I guess it is seldom used. Let's put it in a
        // string value ...
        builder.value(((LocalDate) v).toString());
      }
      else if (Instant.class.isInstance(v)) {
        final XSDateTime o = AttributeBuilder.createValueObject(XSDateTime.TYPE_NAME, XSDateTime.class);
        o.setValue((Instant) v);
        builder.value(o);
      }
      else {
        throw new AttributeException(String.format("Unsupported attribute value type %s for %s",
            v.getClass().getSimpleName(), attribute.getIdentifier()));
      }
    }

    return builder.build();
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
    if (attribute.getAttributeValues().isEmpty()) {
      throw new AttributeException("Invalid SAML attribute - missing value(s)");
    }
    // Assert that all values have the same type and return this type.
    final Class<?> valueType = processValueType(attribute.getAttributeValues());
    AbstractSamlIdentityAttribute<?> genericAttribute;

    if (XSString.class.isAssignableFrom(valueType) || XSAny.class.isAssignableFrom(valueType)) {
      genericAttribute = new StringSamlIdentityAttribute(attributeName, friendlyName,
          AttributeUtils.getAttributeValues(attribute, XSString.class).stream()
              .map(XSString::getValue)
              .collect(Collectors.toList()));
    }
    else if (XSBoolean.class.isAssignableFrom(valueType)) {
      genericAttribute = new BooleanSamlIdentityAttribute(attributeName, friendlyName,
          AttributeUtils.getAttributeValues(attribute, XSBoolean.class).stream()
              .map(XSBoolean::getValue)
              .map(XSBooleanValue::getValue)
              .collect(Collectors.toList()));
    }
    else if (XSInteger.class.isAssignableFrom(valueType)) {
      genericAttribute = new IntegerSamlIdentityAttribute(attributeName, friendlyName,
          AttributeUtils.getAttributeValues(attribute, XSInteger.class).stream()
              .map(XSInteger::getValue)
              .collect(Collectors.toList()));
    }
    else if (XSDateTime.class.isAssignableFrom(valueType)) {
      genericAttribute = new InstantSamlIdentityAttribute(attributeName, friendlyName,
          AttributeUtils.getAttributeValues(attribute, XSDateTime.class).stream()
              .map(XSDateTime::getValue)
              .collect(Collectors.toList()));
    }
    else {
      throw new AttributeException(
          String.format("Unsupported attribute value type %s for %s", valueType.getSimpleName(), attributeName));
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
  private static Class<?> processValueType(final List<XMLObject> values) throws AttributeException {
    final Iterator<XMLObject> i = values.iterator();
    final Class<?> type = i.next().getClass();
    while (i.hasNext()) {
      if (!type.isInstance(i.next())) {
        throw new AttributeException("Multi-valued SAML attribute has different value types - this is not supported");
      }
    }
    return type;
  }

}
