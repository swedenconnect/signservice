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

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import se.swedenconnect.signservice.storage.MessageReplayChecker;

/**
 * Test cases for SamlAuthenticationHandlerConfiguration.
 */
public class SamlAuthenticationHandlerConfigurationTest {

  @Test
  public void testDefaultFactory() {
    final SamlAuthenticationHandlerConfiguration config = new SamlAuthenticationHandlerConfiguration();
    Assertions.assertEquals(SamlAuthenticationHandlerFactory.class.getName(), config.getFactoryClass());
  }

  @Test
  public void testExcludeFromRecursiveMerge() {
    final TestConfig config = new TestConfig();
    final List<Class<?>> excluded = config.getExcludedClasses();
    Assertions.assertEquals(MessageReplayChecker.class, excluded.get(excluded.size() - 2));
    Assertions.assertEquals(EntityDescriptor.class, excluded.get(excluded.size() - 1));
    Assertions.assertEquals(excluded, config.getExcludedClasses());
  }

  private static class TestConfig extends SamlAuthenticationHandlerConfiguration {

    public List<Class<?>> getExcludedClasses() {
      return this.excludeFromRecursiveMerge();
    }

  }

}
