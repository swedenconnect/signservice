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
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.cglib.proxy.Enhancer;
import org.springframework.cglib.proxy.LazyLoader;
import org.springframework.context.ApplicationContext;

import se.swedenconnect.signservice.core.SignServiceHandler;
import se.swedenconnect.signservice.core.config.BeanLoader;

/**
 * A Spring bean loader.
 */
public class SpringBeanLoader<T extends SignServiceHandler> implements BeanLoader<T> {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(SpringBeanLoader.class);

  /** The Spring application context. */
  private final ApplicationContext applicationContext;

  /** The type of handler loaded by this loader instance. */
  private final Class<T> handlerType;

  /**
   * Constructor assigning the Spring application context and the the class for handlers loaded by this instance.
   *
   * @param applicationContext the Spring application context
   * @param handlerType the type of handler loaded
   */
  public SpringBeanLoader(@Nonnull final ApplicationContext applicationContext, @Nonnull final Class<T> handlerType) {
    this.applicationContext = applicationContext;
    this.handlerType = handlerType;
  }

  /**
   * Loads the bean identified with {@code beanName}.
   */
  @Override
  @Nonnull
  public T apply(@Nonnull final String beanName) {
    try {
      final T handler = this.applicationContext.getBean(beanName, this.handlerType);
      log.debug("Bean '{}' of type '{}' was successfully loaded", beanName, this.handlerType.getSimpleName());
      return handler;
    }
    catch (final NoSuchBeanDefinitionException e) {
      log.info("Bean '{}' was not found, possibly not created yet, creating a lazy proxy for the bean ...");
    }
    catch (final BeansException e) {
      log.error("Failed to load bean {} - {}", beanName, e.getMessage(), e);
      throw e;
    }

    // OK, the bean was not found. We assume that it hasn't been created yet and create a proxy.
    // This is pretty much the same as lazy loading, but if the bean isn't available when all beans
    // have been setup, we'll get an error.
    //
    final Enhancer enhancer = new Enhancer();
    enhancer.setSuperclass(this.handlerType);
    enhancer.setCallback(new LazyLoader() {

      @Override
      public Object loadObject() throws Exception {
        return applicationContext.getBean(beanName, handlerType);
      }
    });
    return this.handlerType.cast(enhancer.create());
  }

}
