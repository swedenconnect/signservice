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
package se.swedenconnect.signservice.core;

import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Abstract base class for {@link SignServiceHandler} classes.
 */
public abstract class AbstractSignServiceHandler implements SignServiceHandler {

  /** The handler name. */
  private String name;

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getName() {
    return Optional.ofNullable(this.name).orElse(this.getClass().getSimpleName());
  }

  /**
   * Assigns the handler name. If supplied with {@code null} the simple name of the handler class will be used.
   *
   * @param name the name
   */
  public void setName(@Nullable final String name) {
    this.name = name;
  }

}
