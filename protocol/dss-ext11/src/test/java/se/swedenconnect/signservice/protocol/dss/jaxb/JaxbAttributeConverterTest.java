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

import java.util.Arrays;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import se.swedenconnect.schemas.saml_2_0.assertion.Attribute;
import se.swedenconnect.signservice.core.attribute.AttributeException;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.attribute.SamlIdentityAttribute;
import se.swedenconnect.signservice.core.attribute.impl.StringSamlIdentityAttribute;

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
  public void testConvertAndBack() throws AttributeException {
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

  // TODO: More here

}
