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
package se.swedenconnect.signservice.signature.testutils;

import lombok.Getter;
import org.apache.xml.security.signature.XMLSignature;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.algorithms.MessageDigestAlgorithm;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;

/**
 * Algorithms used in tests
 */
public class TestAlgorithms {

  @Getter public static SignatureAlgorithm rsaPssSha256;
  @Getter public static SignatureAlgorithm rsaPssSha384;
  @Getter public static SignatureAlgorithm rsaPssSha512;
  @Getter public static SignatureAlgorithm rsaSha256;
  @Getter public static SignatureAlgorithm rsaSha384;
  @Getter public static SignatureAlgorithm rsaSha512;
  @Getter public static SignatureAlgorithm ecdsaSha256;
  @Getter public static SignatureAlgorithm ecdsaSha384;
  @Getter public static SignatureAlgorithm ecdsaSha512;
  @Getter public static MessageDigestAlgorithm sha256;
  @Getter public static MessageDigestAlgorithm sha384;
  @Getter public static MessageDigestAlgorithm sha512;

  static {
    AlgorithmRegistrySingleton algoRegistry = AlgorithmRegistrySingleton.getInstance();
    // Signature algorithms
    rsaPssSha256 = (SignatureAlgorithm) algoRegistry.getAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1);
    rsaPssSha384 = (SignatureAlgorithm) algoRegistry.getAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1);
    rsaPssSha512 = (SignatureAlgorithm) algoRegistry.getAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1);
    rsaSha256 = (SignatureAlgorithm) algoRegistry.getAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
    rsaSha384 = (SignatureAlgorithm) algoRegistry.getAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384);
    rsaSha512 = (SignatureAlgorithm) algoRegistry.getAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512);
    ecdsaSha256 = (SignatureAlgorithm) algoRegistry.getAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256);
    ecdsaSha384 = (SignatureAlgorithm) algoRegistry.getAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA384);
    ecdsaSha512 = (SignatureAlgorithm) algoRegistry.getAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA512);
    // Message digest algorithms
    sha256 = rsaSha256.getMessageDigestAlgorithm();
    sha384 = rsaSha384.getMessageDigestAlgorithm();
    sha512 = rsaSha512.getMessageDigestAlgorithm();

  }

}
