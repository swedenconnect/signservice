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
package se.swedenconnect.signservice.core.config.spring;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.beans.BeansException;
import org.springframework.beans.FatalBeanException;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;

import se.swedenconnect.signservice.core.AbstractSignServiceHandler;

/**
 * Test cases for SpringBeanLoader.
 */
public class SpringBeanLoaderTest {

  @SuppressWarnings("unchecked")
  @Test
  public void testLoadDirectly() {
    final DummyHandler handler = new DummyHandler();
    handler.setName("dummy");

    final ApplicationContext context = Mockito.mock(ApplicationContext.class);
    Mockito.when(context.getBean(Mockito.anyString(), ArgumentMatchers.any(Class.class)))
        .thenReturn(handler);

    final SpringBeanLoader loader = new SpringBeanLoader(context);

    final DummyHandler handler2 = loader.load("bean.name", DummyHandler.class);
    Assertions.assertNotNull(handler2);
    Assertions.assertEquals("dummy", handler2.getName());
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testLoadError() {
    final DummyHandler handler = new DummyHandler();
    handler.setName("dummy");

    final ApplicationContext context = Mockito.mock(ApplicationContext.class);
    Mockito.when(context.getBean(Mockito.anyString(), ArgumentMatchers.any(Class.class)))
        .thenThrow(new FatalBeanException("error"));

    final SpringBeanLoader loader = new SpringBeanLoader(context);

    Assertions.assertThrows(BeansException.class, () -> {
      loader.load("bean.name", DummyHandler.class);
    });
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testNotFound() {
    final DummyHandler handler = new DummyHandler();
    handler.setName("dummy");

    final ApplicationContext context = Mockito.mock(ApplicationContext.class);
    Mockito.when(context.getBean(Mockito.anyString(), ArgumentMatchers.any(Class.class)))
        .thenThrow(new NoSuchBeanDefinitionException("not found"));

    final SpringBeanLoader loader = new SpringBeanLoader(context);

    Assertions.assertThrows(NoSuchBeanDefinitionException.class, () -> {
      loader.load("bean.name", DummyHandler.class);
    });

  }

  public static class DummyHandler extends AbstractSignServiceHandler {
  }

}
