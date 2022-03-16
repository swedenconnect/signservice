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
package se.swedenconnect.signservice.core.session;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.api.session.SignServiceContext;
import se.swedenconnect.signservice.api.session.SignServiceSession;
import se.swedenconnect.signservice.api.session.SignServiceSessionSingleton;

/**
 * Test cases for SignServiceSessionSingleton.
 */
public class SignServiceSessionSingletonTest {

  @Test
  public void testEmpty() {
    // Should be null since no init has been done
    Assertions.assertNull(SignServiceSessionSingleton.getSession());
  }

  @Test
  public void testInit() {
    try {
      SignServiceSessionSingleton.init(new MockedSignServiceSession("ABC123"));
      Assertions.assertEquals("ABC123", SignServiceSessionSingleton.getSession().getSessionId());
    }
    finally {
      SignServiceSessionSingleton.clear();
    }
  }

  @Test
  public void testClear() {
    SignServiceSessionSingleton.init(new MockedSignServiceSession("ABC123"));
    Assertions.assertEquals("ABC123", SignServiceSessionSingleton.getSession().getSessionId());
    SignServiceSessionSingleton.clear();
    Assertions.assertNull(SignServiceSessionSingleton.getSession());
  }

  private static class MockedSignServiceSession implements SignServiceSession {

    private final String sessionId;

    public MockedSignServiceSession(final String sessionId) {
      this.sessionId = sessionId;
    }

    @Override
    public String getSessionId() {
      return this.sessionId;
    }

    @Override
    public <T extends Serializable> T getSessionAttribute(String name)
        throws IllegalStateException {
      return null;
    }

    @Override
    public <T extends Serializable> T getSessionAttribute(String name, Class<T> type)
        throws IllegalStateException, ClassCastException {
      return null;
    }

    @Override
    public SignServiceContext getSignServiceContext() throws IllegalStateException {
      return null;
    }

    @Override
    public List<String> getSessionAttributeNames() throws IllegalStateException {
      return null;
    }

    @Override
    public <T extends Serializable> void setSessionAttribute(String name, T attribute)
        throws IllegalStateException {
    }

    @Override
    public void setSignServiceContext(SignServiceContext context) throws IllegalStateException {
    }

    @Override
    public void removeSessionAttribute(String name) throws IllegalStateException {
    }

    @Override
    public void invalidate() {
    }

    @Override
    public Instant getCreationTime() throws IllegalStateException {
      return null;
    }

    @Override
    public Instant getLastAccessedTime() throws IllegalStateException {
      return null;
    }

  }
}
