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

import javax.annotation.Nonnull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;

import se.swedenconnect.signservice.core.config.BeanLoader;

/**
 * A Spring bean loader.
 */
public class SpringBeanLoader implements BeanLoader {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(SpringBeanLoader.class);

  /** The Spring application context. */
  private final ApplicationContext applicationContext;

  /**
   * Constructor assigning the Spring application context.
   *
   * @param applicationContext the Spring application context
   */
  public SpringBeanLoader(@Nonnull final ApplicationContext applicationContext) {
    this.applicationContext = applicationContext;
  }

  /**
   * Loads the bean identified with {@code beanName}.
   */
  @Override
  @Nonnull
  public <T> T load(@Nonnull final String beanName, @Nonnull final Class<T> type) {
    try {
      final T bean = this.applicationContext.getBean(beanName, type);
      log.debug("Bean '{}' of type '{}' was successfully loaded", beanName, type.getSimpleName());
      return bean;
    }
    catch (final BeansException e) {
      log.error("Failed to load bean {} - {}", beanName, e.getMessage(), e);
      throw e;
    }
  }

}
