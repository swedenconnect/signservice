/*
 * Copyright 2022-2024 Sweden Connect
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
package se.swedenconnect.signservice.engine;

import se.swedenconnect.signservice.engine.config.EngineConfiguration;
import se.swedenconnect.signservice.engine.session.EngineContext;
import se.swedenconnect.signservice.protocol.SignRequestMessage;

/**
 * Interface for verifying a {@link SignRequestMessage}.
 */
public interface SignRequestMessageVerifier {

  /**
   * Verifies a {@link SignRequestMessage}. The verification includes signature verification and checks on the actual
   * message to ensure that what is requested is accepted by the SignService engine.
   *
   * @param signRequestMessage the sign request message
   * @param configuration the engine configuration
   * @param context the engine context
   * @throws UnrecoverableSignServiceException for unrecovetable errors
   * @throws SignServiceErrorException for errors that will yield an error response being sent back to the client
   */
  void verifyMessage(final SignRequestMessage signRequestMessage, final EngineConfiguration configuration,
      final EngineContext context) throws UnrecoverableSignServiceException, SignServiceErrorException;

}
