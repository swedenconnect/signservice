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
package se.swedenconnect.signservice.certificate.base.config;

import java.util.List;

import javax.annotation.Nonnull;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMapper;

/**
 * Test cases for AbstractKeyAndCertificateHandlerConfiguration.
 */
public class AbstractKeyAndCertificateHandlerConfigurationTest {

  @Test
  public void testExclude() {
    final ConfigTest cfg = new ConfigTest();
    final List<Class<?>> classesToExcludeFromMerge = cfg.testExcludeFromRecursiveMerge();
    Assertions.assertEquals(
        List.of(PkiCredential.class, AlgorithmRegistry.class, AttributeMapper.class),
        classesToExcludeFromMerge);

    // Verify that the response is cached
    final List<Class<?>> classesToExcludeFromMerge2 = cfg.testExcludeFromRecursiveMerge();
    Assertions.assertEquals(classesToExcludeFromMerge, classesToExcludeFromMerge2);
  }

  private static class ConfigTest extends AbstractKeyAndCertificateHandlerConfiguration {

    public List<Class<?>> testExcludeFromRecursiveMerge() {
      return this.excludeFromRecursiveMerge();
    }

    @Override
    @Nonnull
    protected String getDefaultFactoryClass() {
      return "dummy";
    }

  }

}
