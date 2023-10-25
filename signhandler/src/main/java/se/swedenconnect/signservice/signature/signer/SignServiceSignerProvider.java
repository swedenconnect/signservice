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
package se.swedenconnect.signservice.signature.signer;

import jakarta.annotation.Nonnull;
import se.swedenconnect.signservice.signature.SignatureType;

/**
 * Interface for sign service signer provider
 */
public interface SignServiceSignerProvider {

  /**
   * Get a sign service signer for a given signature algorithm and signature type
   *
   * @param signatureAlgorithm the signature algorithm to use
   * @param signatureType the type of signature that is being created (typically, XML, PDF or JSON)
   * @return {@link SignServiceSigner} for the given algorithm and signature type
   */
  SignServiceSigner getSigner(@Nonnull final String signatureAlgorithm, @Nonnull final SignatureType signatureType);

}
