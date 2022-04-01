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
package se.swedenconnect.signservice.session;

/**
 * Singleton that holds a session object in thread local storage (TLS). This object will be initiated by the SignService
 * Engine and may be used by SignService modules that need access to other session attributes than
 * {@link SignServiceContext} (which is always supplied).
 */
public class SignServiceSessionSingleton {

  /** The session. */
  private SignServiceSession session;

  /** The ThreadLocal ... */
  private final static ThreadLocal<SignServiceSessionSingleton> THREAD_LOCAL = new ThreadLocal<SignServiceSessionSingleton>() {
    @Override
    protected SignServiceSessionSingleton initialValue() {
      return new SignServiceSessionSingleton();
    }
  };

  /**
   * Is called to initialize the singleton with the session it should carry.
   *
   * @param session the session object
   */
  public static void init(final SignServiceSession session) {
    THREAD_LOCAL.get().session = session;
  }

  /**
   * Gets the session object from the TLS.
   *
   * @return the session object, or null if none has been set
   */
  public static SignServiceSession getSession() {
    return THREAD_LOCAL.get().session;
  }

  /**
   * Removes the current session.
   */
  public static void clear() {
    THREAD_LOCAL.remove();
  }

  // Hidden constructor
  private SignServiceSessionSingleton() {
  }

}
