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

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.Objects;

import jakarta.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.algorithms.RSAPSSSignatureAlgorithm;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.signservice.signature.signer.crypto.PKCS1V15Padding;
import se.swedenconnect.signservice.signature.signer.crypto.PkCrypto;

/**
 * Signer for creating RSA signatures using PKCS#1 version 1.5
 */
@Slf4j
public class SignServiceRSASigner implements SignServiceSigner {

  /** {@inheritDoc} */
  @Override public byte[] sign(@Nonnull final byte[] toBeSignedBytes, @Nonnull final PrivateKey privateKey,
    @Nonnull final SignatureAlgorithm signatureAlgorithm) throws SignatureException {

    if (toBeSignedBytes == null) {
      throw new SignatureException("bytes to be signed must not be null");
    }

    Objects.requireNonNull(privateKey, "privateKey must not be null");
    Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm must not be null");

    if (!signatureAlgorithm.getKeyType().equalsIgnoreCase("RSA")) {
      throw new SignatureException("The algorithm is not an RSA algorithm");
    }

    if (signatureAlgorithm instanceof RSAPSSSignatureAlgorithm) {
      throw new SignatureException("The specified algorithm is an RSA PSS algorithm - RSA with PKCS#1 1.5 is required");
    }

    try {
      final MessageDigest md = MessageDigest.getInstance(signatureAlgorithm.getMessageDigestAlgorithm().getJcaName());
      final byte[] hashValue = md.digest(toBeSignedBytes);
      return PkCrypto.rsaSign(
        PKCS1V15Padding.getRSAPkcs1DigestInfo(signatureAlgorithm.getMessageDigestAlgorithm(), hashValue), privateKey);
    }
    catch (Exception ex) {
      log.debug("Error creating RSA signature with algorithm {}", signatureAlgorithm, ex);
      throw new SignatureException(ex);
    }
  }

}
