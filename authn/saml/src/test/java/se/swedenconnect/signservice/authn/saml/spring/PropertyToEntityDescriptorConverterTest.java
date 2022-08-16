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
package se.swedenconnect.signservice.authn.saml.spring;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.context.ApplicationContext;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import se.swedenconnect.signservice.authn.saml.OpenSamlTestBase;

/**
 * Test cases for PropertyToEntityDescriptorConverter.
 */
public class PropertyToEntityDescriptorConverterTest extends OpenSamlTestBase {

  @Test
  public void testCreate() {
    final Resource resource = new ClassPathResource("metadata.xml");
    final ApplicationContext context = Mockito.mock(ApplicationContext.class);
    Mockito.when(context.getResource(Mockito.anyString())).thenReturn(resource);

    final PropertyToEntityDescriptorConverter converter = new PropertyToEntityDescriptorConverter();
    converter.setApplicationContext(context);

    final EntityDescriptor ed = converter.convert("classpath:metadata.xml");
    Assertions.assertNotNull(ed);
  }

  @Test
  public void testBadMetadata() {
    final Resource resource = new ClassPathResource("simplelogger.properties");
    final ApplicationContext context = Mockito.mock(ApplicationContext.class);
    Mockito.when(context.getResource(Mockito.anyString())).thenReturn(resource);

    final PropertyToEntityDescriptorConverter converter = new PropertyToEntityDescriptorConverter();
    converter.setApplicationContext(context);

    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      converter.convert("classpath:simplelogger.properties");
    });
  }

}
