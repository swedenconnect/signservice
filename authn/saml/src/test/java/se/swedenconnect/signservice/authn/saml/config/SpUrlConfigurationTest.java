/*
 * Copyright 2022-2024 Sweden Connect
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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for SpUrlConfiguration.
 */
public class SpUrlConfigurationTest {

  @Test
  public void testUsage() {
    final SpUrlConfiguration conf = new SpUrlConfiguration();
    conf.setBaseUrl("https://www.example.com");
    conf.setAssertionConsumerPath("/saml/response");
    conf.setAdditionalAssertionConsumerPath("/saml/response2");
    conf.setMetadataPublishingPath("/metadata");

    Assertions.assertEquals("https://www.example.com", conf.getBaseUrl());
    Assertions.assertEquals("/saml/response", conf.getAssertionConsumerPath());
    Assertions.assertEquals("/saml/response2", conf.getAdditionalAssertionConsumerPath());
    Assertions.assertEquals("/metadata", conf.getMetadataPublishingPath());

    Assertions.assertEquals(
        "base-url='https://www.example.com', assertion-consumer-path='/saml/response', "
            + "additional-assertion-consumer-path='/saml/response2', metadata-publishing-path='/metadata'",
        conf.toString());

    conf.setAdditionalAssertionConsumerPath(null);
    Assertions.assertNull(conf.getAdditionalAssertionConsumerPath());
    Assertions.assertEquals(
        "base-url='https://www.example.com', assertion-consumer-path='/saml/response', "
            + "metadata-publishing-path='/metadata'",
        conf.toString());
  }

  @Test
  public void testBadParameters() {
    final SpUrlConfiguration conf = new SpUrlConfiguration();

    Assertions.assertThrows(NullPointerException.class, () -> {
      conf.setBaseUrl(null);
    }, "baseUrl must not be null");
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      conf.setBaseUrl("https://www.example.com/");
    }, "The baseUrl must not end with a '/'");

    Assertions.assertThrows(NullPointerException.class, () -> {
      conf.setAssertionConsumerPath(null);
    }, "assertionConsumerPath must not be null");
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      conf.setAssertionConsumerPath("path");
    }, "The assertionConsumerPath must begin with a '/'");

    Assertions.assertDoesNotThrow(() -> {
      conf.setAdditionalAssertionConsumerPath(null);
    });
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      conf.setAdditionalAssertionConsumerPath("path");
    }, "The additionalAssertionConsumerPath must begin with a '/'");


    Assertions.assertThrows(NullPointerException.class, () -> {
      conf.setMetadataPublishingPath(null);
    }, "metadataPublishingPath must not be null");
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      conf.setMetadataPublishingPath("path");
    }, "The metadataPublishingPath must begin with a '/'");
  }

}
