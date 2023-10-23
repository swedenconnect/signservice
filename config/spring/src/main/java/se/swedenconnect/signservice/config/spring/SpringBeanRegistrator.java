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
package se.swedenconnect.signservice.config.spring;

import java.util.Objects;

import javax.annotation.Nonnull;

import org.springframework.context.ConfigurableApplicationContext;

import se.swedenconnect.signservice.config.BeanRegistrator;

/**
 * A simple bean registrator for Spring.
 */
public class SpringBeanRegistrator implements BeanRegistrator {

  /** The Spring application context. */
  private final ConfigurableApplicationContext context;

  /**
   * Constructor.
   *
   * @param context the Spring application context
   */
  public SpringBeanRegistrator(@Nonnull final ConfigurableApplicationContext context) {
    this.context = Objects.requireNonNull(context, "context must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public <T> void registerBean(@Nonnull final String beanName, @Nonnull final Class<T> type, @Nonnull final T bean)
      throws Exception {
    this.context.getBeanFactory().registerSingleton(beanName, bean);
  }

}
