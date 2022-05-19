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
package se.swedenconnect.signservice.certificate.base.keyprovider;

import se.swedenconnect.signservice.session.SignServiceContext;

import java.security.KeyException;
import java.security.KeyPair;
import java.util.List;

/**
 * Interface for a signing key provider that provides signing keys to the signing service.
 */
public interface SignServiceSigningKeyProvider {

  /**
   * Generates or obtains a key pair for the signer
   *
   * @param keytype the key type to obtain or create
   * @param context optional context data that may provide additional information on the source of the key or on how to generate it
   * @return key pair
   * @throws KeyException if key generation was unsuccessful or the intended key could not be obtained
   */
  KeyPair getSigningKeyPair(final String keytype, final SignServiceContext context) throws KeyException;

  /**
   * Return a list of key type identifiers supported by this key provider
   *
   * @return list of supported key types
   */
  List<String> getSupportedKeyTypes();

}
