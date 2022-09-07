/*
 * Copyright 2022 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.swedenconnect.signservice.session.impl;

import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import javax.servlet.http.HttpSession;

import se.swedenconnect.signservice.session.SignServiceSession;

/**
 * {@link SignServiceSession} implementation where sessions are backed by underlying {@link HttpSession} objects.
 */
class DefaultSignServiceSession implements SignServiceSession {

  private final HttpSession inner;

  /**
   * Private constructor.
   *
   * @param httpSession The underlying session object. Must not be null
   * @throws NullPointerException in case httpSession is null
   */
  DefaultSignServiceSession(final HttpSession httpSession) {
    this.inner = Objects.requireNonNull(httpSession, "httpSession cannot be null");
  }

  /** {@inheritDoc} */
  @Override
  public String getId() {
    return this.inner.getId();
  }

  /** {@inheritDoc} */
  @SuppressWarnings("unchecked")
  @Override
  public <T extends Serializable> T getAttribute(final String name) throws IllegalStateException, ClassCastException {
    return (T) this.inner.getAttribute(name);
  }

  /** {@inheritDoc} */
  @Override
  public <T extends Serializable> T getAttribute(final String name, final Class<T> type)
      throws IllegalStateException, ClassCastException {
    return type.cast(this.inner.getAttribute(name));
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getAttributeNames() throws IllegalStateException {
    return Collections.list(this.inner.getAttributeNames());
  }

  /** {@inheritDoc} */
  @Override
  public <T extends Serializable> void setAttribute(final String name, final T attribute) throws IllegalStateException {
    this.inner.setAttribute(name, attribute);
  }

  /** {@inheritDoc} */
  @Override
  public void removeAttribute(final String name) throws IllegalStateException {
    this.inner.removeAttribute(name);
  }

  /** {@inheritDoc} */
  @Override
  public void invalidate() {
    this.inner.invalidate();
  }

  /** {@inheritDoc} */
  @Override
  public Instant getCreationTime() throws IllegalStateException {
    return Instant.ofEpochMilli(this.inner.getCreationTime());
  }

  /** {@inheritDoc} */
  @Override
  public Instant getLastAccessedTime() throws IllegalStateException {
    return Instant.ofEpochMilli(this.inner.getLastAccessedTime());
  }

}
