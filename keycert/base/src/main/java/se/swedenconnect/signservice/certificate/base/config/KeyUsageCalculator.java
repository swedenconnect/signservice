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
package se.swedenconnect.signservice.certificate.base.config;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.asn1.x509.KeyUsage;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

/**
 * Utility class that is used to calculate the key usage value based on the key type and {link
 * SigningKeyUsageDirective}.
 */
public class KeyUsageCalculator {

  /**
   * Calculates the key usage value based on the key type and {link SigningKeyUsageDirective}.
   *
   * @param publicKey the public key
   * @param usageDirective the usage directive (may be null)
   * @return a key usage value
   */
  public static int getKeyUsageValue(
      @Nonnull final PublicKey publicKey, @Nullable final SigningKeyUsageDirective usageDirective) {

    int keyUsage = KeyUsage.digitalSignature + KeyUsage.nonRepudiation;

    if (usageDirective != null) {
      if (usageDirective.isEncrypt()) {
        keyUsage += (RSAPublicKey.class.isInstance(publicKey) ? KeyUsage.keyEncipherment : KeyUsage.keyAgreement);
      }
      if (usageDirective.isExcludeNonRepudiation()) {
        keyUsage -= KeyUsage.nonRepudiation;
      }
    }
    return keyUsage;
  }

  // Private constructor
  private KeyUsageCalculator() {}

}
