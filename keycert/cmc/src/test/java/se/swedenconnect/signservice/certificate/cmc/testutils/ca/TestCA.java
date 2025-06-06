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

package se.swedenconnect.signservice.certificate.cmc.testutils.ca;

import java.security.KeyPair;

import lombok.AllArgsConstructor;
import lombok.Getter;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;
/**
 * Enumeration of configuration data for test CA providers
 */
@AllArgsConstructor
@Getter
public enum TestCA {
  INSTANCE1(
    "rsa-ca",
    "XA",
    "XA RSA Test CA",
    TestServices.rsa2048kp01,
    CAAlgorithmRegistry.ALGO_ID_SIGNATURE_RSA_SHA256,
    "XA RSA OCSP responder",
    TestServices.rsa2048kp02,
    CAAlgorithmRegistry.ALGO_ID_SIGNATURE_RSA_SHA256),

  RSA_PSS_CA(
    "rsa-pss-ca",
    "XB",
    "XB RSA PSS Test CA",
    TestServices.rsa2048kp01,
    CAAlgorithmRegistry.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1,
    "XB RSA PSS OCSP responder",
    TestServices.rsa2048kp02,
    CAAlgorithmRegistry.ALGO_ID_SIGNATURE_RSA_SHA256),
  ECDSA_CA(
    "ecdsa-ca",
    "XC",
    "XC ECDSA Test CA",
    TestServices.ec256kp01,
    CAAlgorithmRegistry.ALGO_ID_SIGNATURE_ECDSA_SHA256,
    "XC ECDSA OCSP responder",
    TestServices.ec256kp02,
    CAAlgorithmRegistry.ALGO_ID_SIGNATURE_ECDSA_SHA256);

  String id;
  String country;
  String caName;
  KeyPair caKeyPair;
  String caAlgo;
  String ocspName;
  KeyPair ocspKeyPair;
  String ocspAlgo;

}
