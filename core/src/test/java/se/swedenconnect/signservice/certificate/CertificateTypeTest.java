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
package se.swedenconnect.signservice.certificate;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for CertificateType.
 */
public class CertificateTypeTest {

  @Test
  public void testFromType() {
    Assertions.assertEquals(CertificateType.PKC, CertificateType.fromType("PKC"));
    Assertions.assertEquals(CertificateType.PKC, CertificateType.fromType("pkc"));
    Assertions.assertEquals(CertificateType.PKC, CertificateType.fromType(CertificateType.PKC.name()));

    Assertions.assertEquals(CertificateType.QC, CertificateType.fromType("QC"));
    Assertions.assertEquals(CertificateType.QC, CertificateType.fromType("qc"));
    Assertions.assertEquals(CertificateType.QC, CertificateType.fromType(CertificateType.QC.name()));

    Assertions.assertEquals(CertificateType.QC_SSCD, CertificateType.fromType("QC/SSCD"));
    Assertions.assertEquals(CertificateType.QC_SSCD, CertificateType.fromType("qc/sscd"));
    Assertions.assertEquals(CertificateType.QC_SSCD, CertificateType.fromType(CertificateType.QC_SSCD.name()));
  }

  @Test
  public void testUnkownType() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      CertificateType.fromType("unknown");
    });
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      CertificateType.fromType(null);
    });
  }

}
