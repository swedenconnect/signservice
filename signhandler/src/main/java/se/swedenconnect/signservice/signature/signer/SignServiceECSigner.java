/*
 * Copyright 2022-2025 Sweden Connect
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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.Objects;

import jakarta.annotation.Nonnull;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.signer.crypto.EcdsaSigValue;
import se.swedenconnect.signservice.signature.signer.crypto.PkCrypto;

/**
 * Implementation of EC signer for calculating the EC signature values
 */
public class SignServiceECSigner implements SignServiceSigner {

  /** Signature type for signatures created by this signer */
  private final SignatureType signatureType;

  /**
   * Constructor
   *
   * @param signatureType signature type served by this signer
   */
  public SignServiceECSigner(final SignatureType signatureType) {
    this.signatureType = signatureType;
  }

  /** {@inheritDoc} */
  @Override
  public byte[] sign(@Nonnull final byte[] toBeSignedBytes, @Nonnull final PrivateKey privateKey,
      @Nonnull final SignatureAlgorithm signatureAlgorithm)
      throws SignatureException {

    if (toBeSignedBytes == null) {
      throw new SignatureException("bytes to be signed must not be null");
    }
    Objects.requireNonNull(privateKey, "privateKey must not be null");
    Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm must not be null");

    try {
      final EcdsaSigValue ecdsaSigVal = PkCrypto.ecdsaSignData(toBeSignedBytes, privateKey, signatureAlgorithm);
      switch (signatureType) {
      case XML:
        return ecdsaSigVal.toByteArray();
      case PDF:
        return ecdsaSigVal.getDEREncodedSigValue();
      default:
        throw new IllegalArgumentException("Unsupported signature type " + signatureType);
      }
    }
    catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new SignatureException(e);
    }
  }
}
