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
package se.swedenconnect.signservice.authn.saml.config;

import java.util.Arrays;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.metadata.AttributeConsumingService;

import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.signservice.authn.saml.OpenSamlTestBase;
import se.swedenconnect.signservice.authn.saml.config.MetadataConfiguration.RequestedAttributeConfig;

/**
 * Test cases for MetadataConfiguration.
 */
public class MetadataConfigurationTest extends OpenSamlTestBase {

  @Test
  public void testCreateAttributeConsumingServiceElement() {
    final MetadataConfiguration config = new MetadataConfiguration();

    Assertions.assertNull(config.createAttributeConsumingServiceElement());

    config.setServiceNames(Arrays.asList());
    Assertions.assertNull(config.createAttributeConsumingServiceElement());

    config.setRequestedAttributes(Arrays.asList());
    Assertions.assertNull(config.createAttributeConsumingServiceElement());

    config.setServiceNames(Arrays.asList(new LocalizedString("en-Demo")));
    final RequestedAttributeConfig rac = new RequestedAttributeConfig();
    rac.setName("urn:oid:1.2.752.29.4.13");
    rac.setRequired(true);
    config.setRequestedAttributes(Arrays.asList(rac));

    AttributeConsumingService service = config.createAttributeConsumingServiceElement();
    Assertions.assertTrue(service.getNames().size() == 1);
    Assertions.assertEquals("Demo", service.getNames().get(0).getValue());
    Assertions.assertEquals("en", service.getNames().get(0).getXMLLang());
    Assertions.assertTrue(service.getRequestedAttributes().size() == 1);
    Assertions.assertEquals("urn:oid:1.2.752.29.4.13", service.getRequestedAttributes().get(0).getName());
    Assertions.assertEquals(Boolean.TRUE, service.getRequestedAttributes().get(0).isRequired());

    config.getRequestedAttributes().get(0).setName(null);
    service = config.createAttributeConsumingServiceElement();
    Assertions.assertTrue(service.getNames().size() == 1);
    Assertions.assertTrue(service.getRequestedAttributes().isEmpty());
  }

}
