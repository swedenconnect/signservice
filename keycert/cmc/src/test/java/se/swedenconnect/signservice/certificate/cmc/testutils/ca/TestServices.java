/*
 * Copyright 2021-2022 Agency for Digital Government (DIGG)
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

import lombok.Getter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.utils.X509Utils;
import se.swedenconnect.signservice.certificate.base.keyprovider.KeyProvider;
import se.swedenconnect.signservice.certificate.base.keyprovider.impl.InMemoryECKeyProvider;
import se.swedenconnect.signservice.certificate.base.keyprovider.impl.OnDemandInMemoryRSAKeyProvider;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

/**
 * This is the top level class for accessing test data and services for unit testing
 *
 * The structure for CA services is the following
 *  - TestCAHolder is a super class for a CA service and related data
 *  - TestCAService holds a CA service. The CA Service in turn consist of a Certificate issuer component that creates the certificates
 *    and the CA repository and revocation services.
 *  - The TestCARepository is a simple implementation of a repository used to store information about issued Certificates
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class TestServices {
  @Getter private static Map<TestCA, TestCAHolder> testCAs;
  @Getter private static Map<ValidatorProfile, CertValidatorComponents> certValidators;
  private static List<X509Certificate> trustAnchors;
  public static KeyPair rsa2048kp01;
  public static KeyPair rsa2048kp02;
  public static KeyPair rsa3072kp;
  public static KeyPair ec256kp01;
  public static KeyPair ec256kp02;
  public static KeyPair ec521kp;

  static {
    testCAs = new HashMap<>();
    certValidators = new HashMap<>();
    trustAnchors = new ArrayList<>();

    try {

      KeyProvider kpRsa2048 = new OnDemandInMemoryRSAKeyProvider(2048);
      KeyProvider kpRsa3072 = new OnDemandInMemoryRSAKeyProvider(3072);
      KeyProvider ecP256 = new InMemoryECKeyProvider(new ECGenParameterSpec("P-256"));
      KeyProvider ecP521 = new InMemoryECKeyProvider(new ECGenParameterSpec("P-521"));


      // Generate user key pais
      log.info("Generating rsa 2048 user key");
      rsa2048kp01 = getKeyPair(kpRsa2048.getKeyPair());
      log.info("Generating rsa 2048 user key");
      rsa2048kp02 = getKeyPair(kpRsa2048.getKeyPair());
      log.info("Generating rsa 3072 user key");
      rsa3072kp = getKeyPair(kpRsa3072.getKeyPair());;
      log.info("Generating ec P256 user key");
      ec256kp01 = getKeyPair(ecP256.getKeyPair());
      log.info("Generating ec P256 user key");
      ec256kp02 = getKeyPair(ecP256.getKeyPair());
      log.info("Generating ec P521 user key");
      ec521kp = getKeyPair(ecP521.getKeyPair());

    }
    catch (Exception ignored) {
    }
  }

  private static KeyPair getKeyPair(PkiCredential pkiCredential) {
    return new KeyPair(pkiCredential.getPublicKey(), pkiCredential.getPrivateKey());
  }

  @SneakyThrows
  public static void addCa(TestCA caConfig) {
    TestCAHolder testCAHolder = new TestCAHolder(caConfig);
    testCAs.put(caConfig, testCAHolder);
    trustAnchors.add(X509Utils.decodeCertificate(testCAHolder.getCscaService().getCaCertificate().getEncoded()));
  }

  public static void addValidators(boolean singleThreaded) {
    certValidators = new HashMap<>();
    Arrays.stream(ValidatorProfile.values()).forEach(profile -> certValidators.put(profile, getValidator(profile, singleThreaded)));
  }

  @SneakyThrows
  public static CertValidatorComponents getValidator(ValidatorProfile profile, boolean singleThreaded) {
    return TestValidatorFactory.getCertificateValidator(trustAnchors, profile, singleThreaded );
  }

}
