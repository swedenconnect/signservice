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

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.utils.X509Utils;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * Signing credentials used by tests
 */
@Slf4j
public class TestCredentials {

  public static PublicKey publicRSAKey;
  public static PrivateKey privateRSAKey;
  public static X509Certificate rsaCertificate;
  public static PublicKey publicECKey;
  public static PrivateKey privateECKey;
  public static X509Certificate ecCertificate;
  // Pre-sign credentials
  public static PublicKey publicRSAPresignKey;
  public static PrivateKey privateRSAPresignKey;
  public static X509Certificate rsaPresignCertificate;
  public static PublicKey publicECPresignKey;
  public static PrivateKey privateECPresignKey;
  public static X509Certificate ecPresignCertificate;

  static {
    try {
      KeyStore rsaKs = KeyStore.getInstance("JKS");
      rsaKs.load(TestCredentials.class.getResourceAsStream("/rsa-signer.jks"), "Test1234".toCharArray());
      publicRSAKey = rsaKs.getCertificate("sign").getPublicKey();
      privateRSAKey = (PrivateKey) rsaKs.getKey("sign", "Test1234".toCharArray());
      rsaCertificate = X509Utils.decodeCertificate(rsaKs.getCertificate("sign").getEncoded());

      KeyStore ecKs = KeyStore.getInstance("JKS");
      ecKs.load(TestCredentials.class.getResourceAsStream("/ec-signer.jks"), "Test1234".toCharArray());
      publicECKey = ecKs.getCertificate("sign").getPublicKey();
      privateECKey = (PrivateKey) ecKs.getKey("sign", "Test1234".toCharArray());
      ecCertificate = X509Utils.decodeCertificate(ecKs.getCertificate("sign").getEncoded());

      KeyStore rsaPresignKs = KeyStore.getInstance("JKS");
      rsaPresignKs.load(TestCredentials.class.getResourceAsStream("/rsa-presigner.jks"), "Test1234".toCharArray());
      publicRSAPresignKey = rsaPresignKs.getCertificate("sign").getPublicKey();
      privateRSAPresignKey = (PrivateKey) rsaPresignKs.getKey("sign", "Test1234".toCharArray());
      rsaPresignCertificate = X509Utils.decodeCertificate(rsaPresignKs.getCertificate("sign").getEncoded());

      KeyStore ecPresignKs = KeyStore.getInstance("JKS");
      ecPresignKs.load(TestCredentials.class.getResourceAsStream("/ec-presigner.jks"), "Test1234".toCharArray());
      publicECPresignKey = ecPresignKs.getCertificate("sign").getPublicKey();
      privateECPresignKey = (PrivateKey) ecPresignKs.getKey("sign", "Test1234".toCharArray());
      ecPresignCertificate = X509Utils.decodeCertificate(ecPresignKs.getCertificate("sign").getEncoded());
    }
    catch (Exception ex) {
      log.error("Unable to load test credentials");
    }

  }

}
