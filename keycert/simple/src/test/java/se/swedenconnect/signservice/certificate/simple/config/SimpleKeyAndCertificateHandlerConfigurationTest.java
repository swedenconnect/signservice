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
package se.swedenconnect.signservice.certificate.simple.config;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for SimpleKeyAndCertificateHandlerConfiguration.
 */
public class SimpleKeyAndCertificateHandlerConfigurationTest {

  @Test
  public void testFactory() {
    final SimpleKeyAndCertificateHandlerConfiguration config = new SimpleKeyAndCertificateHandlerConfiguration();
    Assertions.assertEquals(SimpleKeyAndCertificateHandlerFactory.class.getName(), config.getFactoryClass());
  }

  @Test
  public void testSetBaseUrl() {
    final SimpleKeyAndCertificateHandlerConfiguration config = new SimpleKeyAndCertificateHandlerConfiguration();

    config.setBaseUrl("https://www.example.com");

    assertThatThrownBy(() -> {
      config.setBaseUrl("https://www.example.com/");
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("The baseUrl must not end with a '/'");

    assertThatThrownBy(() -> {
      config.setBaseUrl(null);
    }).isInstanceOf(NullPointerException.class)
        .hasMessage("baseUrl must not be null");
  }

  @Test
  public void testSetCrlDpPath() {
    final SimpleKeyAndCertificateHandlerConfiguration config = new SimpleKeyAndCertificateHandlerConfiguration();

    config.setCrlDpPath("/path/xyz");

    assertThatThrownBy(() -> {
      config.setCrlDpPath("path/xyz");
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("The crlDpPath must begin with a '/'");

    assertThatThrownBy(() -> {
      config.setCrlDpPath(null);
    }).isInstanceOf(NullPointerException.class)
        .hasMessage("crlDpPath must not be null");

  }

}