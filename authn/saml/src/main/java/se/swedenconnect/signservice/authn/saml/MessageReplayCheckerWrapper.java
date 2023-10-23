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
package se.swedenconnect.signservice.authn.saml;

import java.util.Objects;

import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;

import jakarta.annotation.Nonnull;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayException;

/**
 * Wraps a {@link se.swedenconnect.signservice.storage.MessageReplayChecker} in an OpenSAML {@link MessageReplayChecker}.
 */
public class MessageReplayCheckerWrapper implements MessageReplayChecker {

  /** The SignService replay checker. */
  private final se.swedenconnect.signservice.storage.MessageReplayChecker checker;

  /**
   * Constructor accepting the replay checker that we should wrap.
   * @param checker the replay checker
   */
  public MessageReplayCheckerWrapper(@Nonnull final se.swedenconnect.signservice.storage.MessageReplayChecker checker) {
    this.checker = Objects.requireNonNull(checker, "checker must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public void checkReplay(@Nonnull final String id) throws MessageReplayException {
    try {
      this.checker.checkReplay(id);
    }
    catch (final se.swedenconnect.signservice.storage.MessageReplayException e) {
      throw new MessageReplayException(e.getMessage());
    }
  }

  /** {@inheritDoc} */
  @Override
  public void checkReplay(@Nonnull final SAMLObject object) throws MessageReplayException, IllegalArgumentException {
    String id = null;
    if (object instanceof Response) {
      id = ((Response) object).getID();
    }
    else if (object instanceof Assertion) {
      id = ((Assertion) object).getID();
    }
    if (id == null) {
      throw new IllegalArgumentException("Unsupported object type");
    }
    this.checkReplay(id);
  }

}
