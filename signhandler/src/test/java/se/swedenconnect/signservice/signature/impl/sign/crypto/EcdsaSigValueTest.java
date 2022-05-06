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
package se.swedenconnect.signservice.signature.impl.sign.crypto;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testing Ecdsa signature value parser
 */
@Slf4j
class EcdsaSigValueTest {

  static byte[] ec256SigBytes;
  static byte[] ec384SigBytes;
  static byte[] ec521SigBytes;
  static byte[] asymetricEc256SigBytes;
  static List<byte[]> sigValueList;

  @BeforeAll
  static void createTestSigValues() {
    ec256SigBytes = Hex.decode("7945ca368e7b9d24cc5c363e9c0e5949137e53e5ed75c3c3c02ebcc89eb9c4a570"
      + "6a5cbb77eb8379152bca4eb0d49b25a44ea19701c6a6d62c70a1a211f62e16");
    ec384SigBytes = Hex.decode("dfd4463923839d5dfc3b1129c4db8dde58d7836c323a6afc17a8697c80cb36dcabc0ea2e0dc076750d26f0064cb6ee579a1719d2"
      + "d819190f88febcf72b207f2eedf6f5b2d95b0bf3c571f437bb1fa4f92c495bc2f6e211d803c170717ea86202");
    ec521SigBytes = Hex.decode(
      "0127e0a5d11d54106db032ed8e5a34818da0a4794c2e382e603e458106ae78b0eee4005738a32b05f685bcafe59b8f5a8caa17de6362d43323aba997ee4e26f64"
        + "4dc0119a31084bb4986032dea95c2dc65fcbf8bc38779cd257c3bc1073a84681563ad6a33ec5bc3d2a26b0a9f0cc7556ad5cdcd490154d3e95e8ff521b3469284773fa8");
    asymetricEc256SigBytes = Hex.decode("0000ca368e7b9d24cc5c363e9c0e5949137e53e5ed75c3c3c02ebcc89eb9c4a570"
      + "6a5cbb77eb8379152bca4eb0d49b25a44ea19701c6a6d62c70a1a211f62e16");
    sigValueList = List.of(ec256SigBytes, ec384SigBytes, ec521SigBytes, asymetricEc256SigBytes);
  }

  @Test
  void testGetInstance() throws IOException {
    log.info("Testing key initiation");
    for (byte[] sigValue : sigValueList){
      EcdsaSigValue ecdsaSigValue = EcdsaSigValue.getInstance(sigValue);
      BigInteger r = ecdsaSigValue.getR();
      BigInteger s = ecdsaSigValue.getS();
      EcdsaSigValue.getInstance(r, s);
      EcdsaSigValue.getInstance(ecdsaSigValue.toASN1Primitive());
      EcdsaSigValue.getInstance(ecdsaSigValue);
    }

    EcdsaSigValue ecdsaSigValue = EcdsaSigValue.getInstance(ec256SigBytes);
    BigInteger r = ecdsaSigValue.getR();
    BigInteger s = ecdsaSigValue.getS();

    assertThrows(IOException.class, () -> {
      EcdsaSigValue.getInstance(r, BigInteger.TEN).toByteArray();
    });
  }

  @Test
  void getDEREncodedSigValue() throws IOException {
    log.info("Testing export to DER encoded signature values");

    EcdsaSigValue ecSigVal521 = EcdsaSigValue.getInstance(Hex.decode(
      "0127e0a5d11d54106db032ed8e5a34818da0a4794c2e382e603e458106ae78b0eee4005738a32b05f685bcafe59b8f5a8caa17de6362d43323aba997ee4e26f64"
        + "4dc0119a31084bb4986032dea95c2dc65fcbf8bc38779cd257c3bc1073a84681563ad6a33ec5bc3d2a26b0a9f0cc7556ad5cdcd490154d3e95e8ff521b3469284773fa8"));

    String ec521DerHex = Hex.toHexString(ecSigVal521.getDEREncodedSigValue());
    assertEquals("30818802420127e0a5d11d54106db032ed8e5a34818da0a4794c2e382e603e458106ae78b0eee4005738a32b05f685bcafe59b8f5a8caa"
        + "17de6362d43323aba997ee4e26f644dc02420119a31084bb4986032dea95c2dc65fcbf8bc38779cd257c3bc1073a84681563ad6a33ec5bc3d2a26b0a9f0cc7"
        + "556ad5cdcd490154d3e95e8ff521b3469284773fa8"
    , ec521DerHex);
    EcdsaSigValue ecSigVal256 = EcdsaSigValue.getInstance(Hex.decode("7945ca368e7b9d24cc5c363e9c0e5949137e53e5ed75c3c3c02ebcc89eb9c4a570"
      + "6a5cbb77eb8379152bca4eb0d49b25a44ea19701c6a6d62c70a1a211f62e16"));

    String ec256DerHex = Hex.toHexString(ecSigVal256.getDEREncodedSigValue());
    assertEquals("304402207945ca368e7b9d24cc5c363e9c0e5949137e53e5ed75c3c3c02ebcc89eb9c4a50220706a5cbb77eb8379152bca4eb0d49b25a44ea19701c6a6d62c70a1a211f62e16", ec256DerHex);
  }

  @Test
  void toByteArray() throws IOException {
    log.info("Testing export to byte array signature values");

    for (byte[] sigValue : sigValueList) {
      EcdsaSigValue ecdsaSigValue = EcdsaSigValue.getInstance(sigValue);
      String rBytes = Hex.toHexString(ecdsaSigValue.getR().toByteArray());
      String sBytes = Hex.toHexString(ecdsaSigValue.getS().toByteArray());
      assertArrayEquals(sigValue, ecdsaSigValue.toByteArray());
    }
  }


  @Test
  void getSupportedKeyLengths() {
    assertArrayEquals(new int[] { 160, 224, 256, 384, 521 }, EcdsaSigValue.getSupportedKeyLengths());
  }

  @Test
  void setSupportedKeyLengths() {
    EcdsaSigValue.setSupportedKeyLengths(new int[]{256,384,521});
    assertArrayEquals(new int[]{256,384,521}, EcdsaSigValue.getSupportedKeyLengths());
  }

}