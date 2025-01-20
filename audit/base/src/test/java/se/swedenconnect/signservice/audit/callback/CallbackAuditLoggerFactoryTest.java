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
package se.swedenconnect.signservice.audit.callback;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.base.AbstractAuditLoggerConfiguration;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Test cases for CallbackAuditLoggerFactory.
 */
public class CallbackAuditLoggerFactoryTest {

  @Test
  public void testCreate() {
    final CallbackAuditLoggerFactory factory = new CallbackAuditLoggerFactory();
    final CallbackAuditLoggerConfiguration conf = new CallbackAuditLoggerConfiguration();
    conf.setListener((e) -> {});
    final AuditLogger logger = factory.create(conf);
    Assertions.assertTrue(CallbackAuditLogger.class.isInstance(logger));
  }

  @Test
  public void testCreateWithReference() {
    final CallbackAuditLoggerFactory factory = new CallbackAuditLoggerFactory();
    final CallbackAuditLoggerConfiguration conf = new CallbackAuditLoggerConfiguration();
    conf.setListenerRef("ref");
    final BeanLoader beanLoader = new BeanLoader() {

      @Override
      public <T> T load(final String beanName, final Class<T> type) {
        final AuditLoggerListener listener = (e) -> {};
        return type.cast(listener);
      }
    };

    final AuditLogger logger = factory.create(conf, beanLoader);
    Assertions.assertTrue(CallbackAuditLogger.class.isInstance(logger));
  }

  @Test
  public void testCreateWithReferenceMissingBeanLoader() {
    final CallbackAuditLoggerFactory factory = new CallbackAuditLoggerFactory();
    final CallbackAuditLoggerConfiguration conf = new CallbackAuditLoggerConfiguration();
    conf.setListenerRef("ref");
    assertThatThrownBy(() -> {
      factory.create(conf, null);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("No bean loader provided - can not load listener-ref");
  }

  @Test
  public void testCreateWithMissingListener() {
    final CallbackAuditLoggerFactory factory = new CallbackAuditLoggerFactory();
    final CallbackAuditLoggerConfiguration conf = new CallbackAuditLoggerConfiguration();
    assertThatThrownBy(() -> {
      factory.create(conf, null);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing audit logger listener");
  }

  @Test
  public void testNullConfig() {
    final CallbackAuditLoggerFactory factory = new CallbackAuditLoggerFactory();
    assertThatThrownBy(() -> {
      factory.create(null);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing configuration for CallbackAuditLogger");
  }

  @Test
  public void testWrongType() {
    final CallbackAuditLoggerFactory factory = new CallbackAuditLoggerFactory();

    final HandlerConfiguration<AuditLogger> conf = new AbstractAuditLoggerConfiguration() {
      @Override
      protected String getDefaultFactoryClass() {
        return null;
      }
    };
    assertThatThrownBy(() -> {
      factory.create(conf);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unknown configuration object supplied - ");

  }

}
