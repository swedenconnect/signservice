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
package se.swedenconnect.signservice.certificate.cmc.testutils;

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

  public static PublicKey publicCMCClientSignerECKey;
  public static PrivateKey privateCMCClientSignerECKey;
  public static X509Certificate cMCClientSignerCertificate;
  public static PublicKey publicCMCCaSignerECKey;
  public static PrivateKey privateCMCCaSignerECKey;
  public static X509Certificate cMCCaSignerCertificate;

  static {
    try {
      KeyStore ecClientSignerKs = KeyStore.getInstance("JKS");
      ecClientSignerKs.load(TestCredentials.class.getResourceAsStream("/ec-cmc-client-signer.jks"), "Test1234".toCharArray());
      publicCMCClientSignerECKey = ecClientSignerKs.getCertificate("cmc-client-signer").getPublicKey();
      privateCMCClientSignerECKey = (PrivateKey) ecClientSignerKs.getKey("cmc-client-signer", "Test1234".toCharArray());
      cMCClientSignerCertificate = X509Utils.decodeCertificate(ecClientSignerKs.getCertificate("cmc-client-signer").getEncoded());

      KeyStore ecCaSignerKs = KeyStore.getInstance("JKS");
      ecCaSignerKs.load(TestCredentials.class.getResourceAsStream("/ec-cmc-ca-signer.jks"), "Test1234".toCharArray());
      publicCMCCaSignerECKey = ecCaSignerKs.getCertificate("cmc-ca-signer").getPublicKey();
      privateCMCCaSignerECKey = (PrivateKey) ecCaSignerKs.getKey("cmc-ca-signer", "Test1234".toCharArray());
      cMCCaSignerCertificate = X509Utils.decodeCertificate(ecCaSignerKs.getCertificate("cmc-ca-signer").getEncoded());
    }
    catch (Exception ex) {
      log.error("Unable to load test credentials");
    }

  }

}
