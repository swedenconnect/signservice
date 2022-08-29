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
package se.swedenconnect.signservice.signature.signer;

import java.security.PrivateKey;
import java.security.SignatureException;

import javax.annotation.Nonnull;

import se.swedenconnect.security.algorithms.SignatureAlgorithm;

/**
 * Interface for sign service signer used to create signature values.
 */
public interface SignServiceSigner {

  /**
   * Creates a signature value.
   *
   * @param toBeSignedBytes the bytes to be hashed and signed by this signer
   * @param privateKey the private key used to sign
   * @param signatureAlgorithm the signature algorithm used for signing
   * @return signature value
   * @throws SignatureException on errors creating the signature
   */
  byte[] sign(@Nonnull final byte[] toBeSignedBytes, @Nonnull final PrivateKey privateKey,
      @Nonnull final SignatureAlgorithm signatureAlgorithm) throws SignatureException;

}
