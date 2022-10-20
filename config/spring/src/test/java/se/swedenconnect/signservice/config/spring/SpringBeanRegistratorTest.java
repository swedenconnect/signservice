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
package se.swedenconnect.signservice.config.spring;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * Test cases for SpringBeanRegistrator.
 */
public class SpringBeanRegistratorTest {

  @Test
  public void testRegister() throws Exception {
    final ConfigurableApplicationContext context = Mockito.mock(ConfigurableApplicationContext.class);
    final ConfigurableListableBeanFactory bf = Mockito.mock(ConfigurableListableBeanFactory.class);
    Mockito.when(context.getBeanFactory()).thenReturn(bf);

    final SpringBeanRegistrator factory = new SpringBeanRegistrator(context);
    factory.registerBean("name", String.class, new String("Test"));

    Mockito.verify(bf).registerSingleton(Mockito.any(), Mockito.any());
  }

}
