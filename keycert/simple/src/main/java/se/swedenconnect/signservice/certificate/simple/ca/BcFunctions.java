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
package se.swedenconnect.signservice.certificate.simple.ca;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.function.Function;

import org.bouncycastle.cert.X509CertificateHolder;

import se.swedenconnect.security.credential.utils.X509Utils;

/**
 * Utils for working with Bouncy Castle objects.
 */
class BcFunctions {

  /**
   * Function that converts from an {@link X509CertificateHolder} to an {@link X509Certificate}.
   */
  public static Function<X509CertificateHolder, X509Certificate> toX509Certificate = h -> {
    try {
      return X509Utils.decodeCertificate(h.getEncoded());
    }
    catch (CertificateException | IOException e) {
      throw new SecurityException(e);
    }
  };

  /**
   * Function that converts from an {@link X509Certificate} to an {@link X509CertificateHolder}.
   */
  public static Function<X509Certificate, X509CertificateHolder> toX509CertificateHolder = c -> {
    try {
      return new X509CertificateHolder(c.getEncoded());
    }
    catch (CertificateException | IOException e) {
      throw new SecurityException(e);
    }
  };

}
