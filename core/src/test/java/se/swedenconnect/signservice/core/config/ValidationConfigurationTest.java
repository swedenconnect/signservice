/*
 * Copyright 2022-2023 Sweden Connect
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
package se.swedenconnect.signservice.core.config;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for ValidationConfiguration.
 */
public class ValidationConfigurationTest {

  @Test
  public void testDefaults() {
    final ValidationConfiguration conf = new ValidationConfiguration();
    Assertions.assertEquals(ValidationConfiguration.DEFAULT_ALLOWED_CLOCK_SKEW, conf.getAllowedClockSkew());
    Assertions.assertEquals(ValidationConfiguration.DEFAULT_MAX_MESSAGE_AGE, conf.getMaxMessageAge());
  }

  @Test
  public void testSetters() {
    final ValidationConfiguration conf = new ValidationConfiguration();
    conf.setAllowedClockSkew(Duration.ofMinutes(2));

    // Not allowed to change an assigned value ..
    assertThatThrownBy(() -> {
      conf.setAllowedClockSkew(Duration.ofMinutes(2));
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("allowedClockSkew has already been assigned");

    Assertions.assertEquals(Duration.ofMinutes(2), conf.getAllowedClockSkew());

    conf.setMaxMessageAge(Duration.ofMinutes(5));

    assertThatThrownBy(() -> {
      conf.setMaxMessageAge(Duration.ofMinutes(5));
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("maxMessageAge has already been assigned");

    Assertions.assertEquals(Duration.ofMinutes(5), conf.getMaxMessageAge());
  }

  @Test
  public void testSingleton() {
    final ValidationConfiguration conf = new ValidationConfiguration();
    conf.setAllowedClockSkew(Duration.ofMinutes(2));
    conf.setMaxMessageAge(Duration.ofMinutes(5));
    conf.init();

    Assertions.assertEquals(Duration.ofMinutes(2), ValidationConfigurationSingleton.getConfig().getAllowedClockSkew());
    Assertions.assertEquals(Duration.ofMinutes(5), ValidationConfigurationSingleton.getConfig().getMaxMessageAge());
  }

  @Test
  public void testMultipleInit() {
    final ValidationConfiguration conf = new ValidationConfiguration();
    conf.setAllowedClockSkew(Duration.ofMinutes(2));
    conf.setMaxMessageAge(Duration.ofMinutes(5));
    conf.init();

    final ValidationConfiguration conf2 = new ValidationConfiguration();
    conf2.init();

    // The first one should be the one that is used
    Assertions.assertEquals(Duration.ofMinutes(2), ValidationConfigurationSingleton.getConfig().getAllowedClockSkew());
    Assertions.assertEquals(Duration.ofMinutes(5), ValidationConfigurationSingleton.getConfig().getMaxMessageAge());
  }

  @Test
  public void testSingletonDefaults() {
    Assertions.assertEquals(ValidationConfiguration.DEFAULT_ALLOWED_CLOCK_SKEW,
        ValidationConfigurationSingleton.getConfig().getAllowedClockSkew());
    Assertions.assertEquals(ValidationConfiguration.DEFAULT_MAX_MESSAGE_AGE,
        ValidationConfigurationSingleton.getConfig().getMaxMessageAge());
  }

}
