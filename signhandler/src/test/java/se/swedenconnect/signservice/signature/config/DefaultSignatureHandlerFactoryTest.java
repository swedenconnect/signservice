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
package se.swedenconnect.signservice.signature.config;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.signservice.core.config.AbstractHandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;
import se.swedenconnect.signservice.signature.SignatureHandler;
import se.swedenconnect.signservice.signature.impl.DefaultSignatureHandler;
import se.swedenconnect.signservice.signature.signer.DefaultSignServiceSignerProvider;
import se.swedenconnect.signservice.signature.tbsdata.XMLTBSDataProcessor;

/**
 * Test cases for DefaultSignatureHandlerFactory.
 */
public class DefaultSignatureHandlerFactoryTest {

  @Test
  public void testNullConfig() {
    final DefaultSignatureHandlerFactory factory = new DefaultSignatureHandlerFactory();
    final SignatureHandler handler = factory.create(null);
    Assertions.assertTrue(DefaultSignatureHandler.class.isInstance(handler));
  }

  @Test
  public void testConfig() {
    final DefaultSignatureHandlerFactory factory = new DefaultSignatureHandlerFactory();
    final DefaultSignatureHandlerConfiguration config = new DefaultSignatureHandlerConfiguration();
    config.setAlgorithmRegistry(AlgorithmRegistrySingleton.getInstance());
    config.setSignerProvider(new DefaultSignServiceSignerProvider(config.getAlgorithmRegistry()));

    final TBSDataProcessorConfiguration c1 = new TBSDataProcessorConfiguration();
    c1.setType("xml");
    c1.setDefaultCanonicalizationAlgorithm("canon-uri");
    c1.setSupportedProcessingRules(Arrays.asList("rule1", "rule2"));

    final TBSDataProcessorConfiguration c2 = new TBSDataProcessorConfiguration();
    c2.setType("pdf");
    c2.setSupportedProcessingRules(Arrays.asList("rule3", "rule4"));
    c2.setIncludeIssuerSerial(true);
    c2.setStrictProcessing(true);

    config.setTbsProcessors(Arrays.asList(c1, c2));

    final SignatureHandler handler = factory.create(config);
    Assertions.assertTrue(DefaultSignatureHandler.class.isInstance(handler));
  }

  @Test
  public void testNoProcessors() {
    final DefaultSignatureHandlerFactory factory = new DefaultSignatureHandlerFactory();
    final DefaultSignatureHandlerConfiguration config = new DefaultSignatureHandlerConfiguration();
    config.setAlgorithmRegistry(AlgorithmRegistrySingleton.getInstance());
    config.setSignerProvider(new DefaultSignServiceSignerProvider(config.getAlgorithmRegistry()));

    final SignatureHandler handler = factory.create(config);
    Assertions.assertTrue(DefaultSignatureHandler.class.isInstance(handler));
  }

  @Test
  public void testDuplicateProcessors() {
    final DefaultSignatureHandlerFactory factory = new DefaultSignatureHandlerFactory();
    final DefaultSignatureHandlerConfiguration config = new DefaultSignatureHandlerConfiguration();

    final TBSDataProcessorConfiguration c1 = new TBSDataProcessorConfiguration();
    c1.setType("xml");
    c1.setSupportedProcessingRules(Arrays.asList("rule1", "rule2"));

    final TBSDataProcessorConfiguration c2 = new TBSDataProcessorConfiguration();
    c2.setType("xml");
    c2.setSupportedProcessingRules(Arrays.asList("rule3", "rule4"));
    c2.setIncludeIssuerSerial(true);
    c2.setStrictProcessing(true);

    config.setTbsProcessors(Arrays.asList(c1, c2));

    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage(
            String.format("Several %s instances configured - not allowed", XMLTBSDataProcessor.class.getSimpleName()));
  }

  @Test
  public void testUnknownType() {
    final DefaultSignatureHandlerFactory factory = new DefaultSignatureHandlerFactory();
    final DefaultSignatureHandlerConfiguration config = new DefaultSignatureHandlerConfiguration();

    final TBSDataProcessorConfiguration c1 = new TBSDataProcessorConfiguration();
    c1.setType("cms");

    config.setTbsProcessors(Arrays.asList(c1));

    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Unsupported type: cms");
  }

  @Test
  public void testMissingType() {
    final DefaultSignatureHandlerFactory factory = new DefaultSignatureHandlerFactory();
    final DefaultSignatureHandlerConfiguration config = new DefaultSignatureHandlerConfiguration();

    final TBSDataProcessorConfiguration c1 = new TBSDataProcessorConfiguration();

    config.setTbsProcessors(Arrays.asList(c1));

    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing type parameter");
  }

  @Test
  public void testUnknownConfig() {
    final DefaultSignatureHandlerFactory factory = new DefaultSignatureHandlerFactory();
    final HandlerConfiguration<SignatureHandler> config = new AbstractHandlerConfiguration<SignatureHandler>() {

      @Override
      protected String getDefaultFactoryClass() {
        return "dummy";
      }
    };
    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unknown configuration object supplied - ");
  }

  @Test
  public void testHandlerType() {
    final DefaultSignatureHandlerFactory2 f = new DefaultSignatureHandlerFactory2();
    Assertions.assertEquals(SignatureHandler.class, f.handler());
  }

  private static class DefaultSignatureHandlerFactory2 extends DefaultSignatureHandlerFactory {

    public Class<SignatureHandler> handler() {
      return this.getHandlerType();
    }
  }

}
