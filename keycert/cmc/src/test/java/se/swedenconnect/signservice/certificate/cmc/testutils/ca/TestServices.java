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
package se.swedenconnect.signservice.certificate.cmc.testutils.ca;

import java.security.KeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import lombok.Getter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.security.credential.container.PkiCredentialContainerException;
import se.swedenconnect.security.credential.container.SoftPkiCredentialContainer;
import se.swedenconnect.security.credential.container.keytype.KeyGenType;
import se.swedenconnect.security.credential.utils.X509Utils;

/**
 * This is the top level class for accessing test data and services for unit testing
 *
 * The structure for CA services is the following
 *  - TestCAHolder is a super class for a CA service and related data
 *  - TestCAService holds a CA service. The CA Service in turn consist of a Certificate issuer component that creates the certificates
 *    and the CA repository and revocation services.
 *  - The TestCARepository is a simple implementation of a repository used to store information about issued Certificates
 */
@Slf4j
public class TestServices {
  @Getter private static Map<TestCA, TestCAHolder> testCAs;
  private static List<X509Certificate> trustAnchors;
  public static KeyPair rsa2048kp01;
  public static KeyPair rsa2048kp02;
  public static KeyPair rsa3072kp;
  public static KeyPair ec256kp01;
  public static KeyPair ec256kp02;
  public static KeyPair ec521kp;

  static {
    testCAs = new HashMap<>();
    trustAnchors = new ArrayList<>();

    try {

      PkiCredentialContainer keyProvider = new SoftPkiCredentialContainer("BC", "Test1234");
      keyProvider.setSupportedKeyTypes(List.of(
        KeyGenType.RSA_2048,
        KeyGenType.RSA_3072,
        KeyGenType.EC_P256,
        KeyGenType.EC_P521
      ));


      // Generate user key pais
      log.info("Generating rsa 2048 user key");
      rsa2048kp01 = getKeyPair(keyProvider, KeyGenType.RSA_2048);
      log.info("Generating rsa 2048 user key");
      rsa2048kp02 = getKeyPair(keyProvider, KeyGenType.RSA_2048);
      log.info("Generating rsa 3072 user key");
      rsa3072kp = getKeyPair(keyProvider, KeyGenType.RSA_3072);;
      log.info("Generating ec P256 user key");
      ec256kp01 = getKeyPair(keyProvider, KeyGenType.EC_P256);
      log.info("Generating ec P256 user key");
      ec256kp02 = getKeyPair(keyProvider, KeyGenType.EC_P256);
      log.info("Generating ec P521 user key");
      ec521kp = getKeyPair(keyProvider, KeyGenType.EC_P521);

    }
    catch (Exception ignored) {
    }
  }

  private static KeyPair getKeyPair(PkiCredentialContainer keyProvider, String keyType)
    throws CertificateException, NoSuchAlgorithmException, KeyException, PkiCredentialContainerException {
    PkiCredential pkiCredential = keyProvider.getCredential(keyProvider.generateCredential(keyType));
    return new KeyPair(pkiCredential.getPublicKey(), pkiCredential.getPrivateKey());
  }

  @SneakyThrows
  public static void addCa(TestCA caConfig) {
    TestCAHolder testCAHolder = new TestCAHolder(caConfig);
    testCAs.put(caConfig, testCAHolder);
    trustAnchors.add(X509Utils.decodeCertificate(testCAHolder.getCscaService().getCaCertificate().getEncoded()));
  }

}
