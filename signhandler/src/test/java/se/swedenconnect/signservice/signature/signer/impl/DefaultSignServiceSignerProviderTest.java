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
package se.swedenconnect.signservice.signature.signer.impl;

import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.signer.SignServiceSignerProvider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for signer provider
 */
@Slf4j
class DefaultSignServiceSignerProviderTest {

  private static SignServiceSignerProvider signServiceSignerProvider;

  @BeforeAll
  static void init() {
    signServiceSignerProvider = new DefaultSignServiceSignerProvider(AlgorithmRegistrySingleton.getInstance());
  }

  @Test
  void getSigner() {
    log.info("Performing tests for signer provider");

    //RSA PSS
    assertEquals(
      SignServiceRSAPSSSigner.class,
      signServiceSignerProvider.getSigner(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1, SignatureType.XML).getClass()
    );
    log.info("Returns RSA-PSS signer for {}", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1);
    assertEquals(
      SignServiceRSAPSSSigner.class,
      signServiceSignerProvider.getSigner(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1, SignatureType.XML).getClass()
    );
    log.info("Returns RSA-PSS signer for {}", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1);
    assertEquals(
      SignServiceRSAPSSSigner.class,
      signServiceSignerProvider.getSigner(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1, SignatureType.XML).getClass()
    );
    log.info("Returns RSA-PSS signer for {}", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1);
    // RSA
    assertEquals(
      SignServiceRSASigner.class,
      signServiceSignerProvider.getSigner(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, SignatureType.XML).getClass()
    );
    log.info("Returns RSA signer for {}", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
    assertEquals(
      SignServiceRSASigner.class,
      signServiceSignerProvider.getSigner(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384, SignatureType.XML).getClass()
    );
    log.info("Returns RSA signer for {}", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384);
    assertEquals(
      SignServiceRSASigner.class,
      signServiceSignerProvider.getSigner(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512, SignatureType.XML).getClass()
    );
    log.info("Returns RSA signer for {}", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512);

    //EC
    assertEquals(
      SignServiceECSigner.class,
      signServiceSignerProvider.getSigner(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, SignatureType.XML).getClass()
    );
    log.info("Returns ECDSA signer for {}", XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256);
    assertEquals(
      SignServiceECSigner.class,
      signServiceSignerProvider.getSigner(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA384, SignatureType.PDF).getClass()
    );
    log.info("Returns ECDSA signer for {}", XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA384);
    assertEquals(
      SignServiceECSigner.class,
      signServiceSignerProvider.getSigner(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA512, SignatureType.XML).getClass()
    );
    log.info("Returns ECDSA signer for {}", XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA512);

  }

  @Test
  void errorTests() {
    log.info("Performing exception test for signer provider");

    individualErrorTest(null, null, NullPointerException.class);
    individualErrorTest(null, SignatureType.XML, NullPointerException.class);
    individualErrorTest(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, null, NullPointerException.class);
    individualErrorTest("http://id.example.com/this-algorithm-is-not-supported", SignatureType.PDF, IllegalArgumentException.class);
  }

  void individualErrorTest(String algo, SignatureType signatureType, Class<? extends Exception> exceptionClass) {
    Exception ex = assertThrows(exceptionClass, () -> {
      signServiceSignerProvider.getSigner(algo, signatureType);
    });
    log.info("Creating signer for algorithm {} and type {} failed with exception: {}", algo, signatureType, ex.toString());
  }

}