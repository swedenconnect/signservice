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
package se.swedenconnect.signservice.core.config;

import javax.annotation.Nonnull;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.signservice.core.AbstractSignServiceHandler;

/**
 * Test cases for AbstractHandlerConfiguration.
 */
public class AbstractHandlerConfigurationTest {

  @Test
  public void testResolveAndMerge() throws Exception {
    final DummyHandlerConfiguration shared = new DummyHandlerConfiguration();
    shared.setDummy(new DummyObject());
    shared.getDummy().setOne("1");
    shared.getDummy().setTwo("2");
    shared.getDummy().setThree(true);
    shared.getDummy().assignFour("4");
    shared.getDummy().assignTheFive("5");
    shared.setDummy2(new DummyObject());
    shared.getDummy2().setOne("1-1");
    shared.getDummy2().setTwo("2-2");
    shared.setDef(17);
    shared.setName("The configuration");

    final DummyHandlerConfiguration conf = new DummyHandlerConfiguration();
    conf.setAbc("ABC");
    conf.setGhi('a');
    conf.setDummy(new DummyObject());
    conf.getDummy().setOne("One");
    conf.setDummy2(new DummyObject());
    conf.getDummy2().setOne("1-1");
    conf.getDummy2().setTwo("2-2");
    conf.setDefaultConfigRef("ref");

    Assertions.assertTrue(conf.needsDefaultConfigResolving());

    // Can't assign both object and ref
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      conf.setDefaultConfig(shared);
    });

    conf.resolveDefaultConfigRef((ref) -> shared);
    conf.init();

    // After a merge the default-config-ref should be null
    Assertions.assertNull(conf.getDefaultConfigRef());

    Assertions.assertEquals("The configuration", conf.getName());
    Assertions.assertEquals("ABC", conf.getAbc());
    Assertions.assertEquals(Integer.valueOf(17), conf.getDef());
    Assertions.assertEquals('a', conf.getGhi());
    Assertions.assertEquals("One", conf.getDummy().getOne());
    Assertions.assertEquals("2", conf.getDummy().getTwo());
    Assertions.assertTrue(conf.getDummy().isThree());
    Assertions.assertEquals("4", conf.getDummy().getFour());
    Assertions.assertNull(conf.getDummy().getFive()); // Couldn't be merged
    Assertions.assertEquals("1-1", conf.getDummy2().getOne());
    Assertions.assertEquals("2-2", conf.getDummy2().getTwo());
  }

  @Test
  public void testFailingResolving() {
    final DummyHandlerConfiguration conf = new DummyHandlerConfiguration();

    // No default-config-ref given
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      conf.resolveDefaultConfigRef((r) -> null);
    });

    conf.setDefaultConfigRef("ref");
    // Ref given but resolver function doesn't find object
    Assertions.assertThrows(NullPointerException.class, () -> {
      conf.resolveDefaultConfigRef((r) -> null);
    });
  }

  @Test
  public void testMerge() throws Exception {
    final DummyHandlerConfiguration shared = new DummyHandlerConfiguration();
    shared.setDummy(new DummyObject());
    shared.getDummy().setOne("1");
    shared.getDummy().setTwo("2");
    shared.getDummy().setThree(true);
    shared.getDummy().assignFour("4");
    shared.getDummy().assignTheFive("5");
    shared.setDummy2(new DummyObject());
    shared.getDummy2().setOne("1-1");
    shared.getDummy2().setTwo("2-2");
    shared.setDef(17);
    shared.setName("The configuration");

    final DummyHandlerConfiguration conf = new DummyHandlerConfiguration();
    conf.setAbc("ABC");
    conf.setGhi('a');
    conf.setDummy(new DummyObject());
    conf.getDummy().setOne("One");
    conf.setDummy2(new DummyObject());
    conf.getDummy2().setOne("1-1");
    conf.getDummy2().setTwo("2-2");
    conf.setDefaultConfig(shared);

    Assertions.assertFalse(conf.needsDefaultConfigResolving());

    // Can't assign both object and ref
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      conf.setDefaultConfigRef("ref");
    });

    // Init merges
    conf.init();

    Assertions.assertNull(conf.getDefaultConfig());

    Assertions.assertEquals("The configuration", conf.getName());
    Assertions.assertEquals("ABC", conf.getAbc());
    Assertions.assertEquals(Integer.valueOf(17), conf.getDef());
    Assertions.assertEquals('a', conf.getGhi());
    Assertions.assertEquals("One", conf.getDummy().getOne());
    Assertions.assertEquals("2", conf.getDummy().getTwo());
    Assertions.assertTrue(conf.getDummy().isThree());
    Assertions.assertEquals("4", conf.getDummy().getFour());
    Assertions.assertNull(conf.getDummy().getFive()); // Couldn't be merged
    Assertions.assertEquals("1-1", conf.getDummy2().getOne());
    Assertions.assertEquals("2-2", conf.getDummy2().getTwo());
  }

  @Test
  public void testNoFactory() {
    final DummyHandlerConfiguration2 conf = new DummyHandlerConfiguration2();

    Assertions.assertNull(conf.getFactoryClass());
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      conf.init();
    });

    conf.setFactoryClass(DummyHandlerFactory2.class.getName());
    Assertions.assertNotNull(conf.getFactoryClass());
    Assertions.assertDoesNotThrow(() -> {
      conf.init();
    });
  }

  public static class DummyHandler extends AbstractSignServiceHandler {
  }

  @EqualsAndHashCode
  public static class DummyObject {
    @Getter
    @Setter
    private String one;

    @Getter
    @Setter
    private String two;

    @Setter
    private Boolean three;

    // No setter!
    @Getter
    private String four;

    // No matching getter and setter (should be ignored)
    private String theFive;

    public Boolean isThree() {
      return this.three;
    }

    public void assignFour(final String four) {
      this.four = four;
    }

    public String getFive() {
      return this.theFive;
    }

    public void assignTheFive(final String five) {
      this.theFive = five;
    }
  }

  @Data
  @EqualsAndHashCode(callSuper = false)
  public static class DummyHandlerConfiguration extends AbstractHandlerConfiguration<DummyHandler> {

    private String abc;
    private Integer def;
    private char ghi;
    private DummyObject dummy;
    private DummyObject dummy2;

    @Override
    @Nonnull
    protected String getDefaultFactoryClass() {
      return DummyHandlerFactory.class.getName();
    }

  }

  public static class DummyHandlerFactory extends AbstractHandlerFactory<DummyHandler> {

    @Override
    @Nonnull
    protected DummyHandler createHandler(@Nonnull final HandlerConfiguration<DummyHandler> configuration)
        throws IllegalArgumentException {
      throw new IllegalArgumentException("Only for test");
    }

  }

  public static class DummyHandlerConfiguration2 extends AbstractHandlerConfiguration<DummyHandler> {

    @Override
    @Nonnull
    protected String getDefaultFactoryClass() {
      return null;
    }
  }

  public static class DummyHandlerFactory2 extends AbstractHandlerFactory<DummyHandler> {

    @Override
    @Nonnull
    protected DummyHandler createHandler(@Nonnull final HandlerConfiguration<DummyHandler> configuration)
        throws IllegalArgumentException {
      throw new IllegalArgumentException("Only for test");
    }

  }

}