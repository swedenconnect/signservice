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
package se.swedenconnect.signservice.certificate.base.config;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.List;

/**
 * Configuration data for a certificate profile
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CertificateProfileConfiguration {

  private List<String> policy;
  private Boolean policyCritical;
  private List<String> eku;
  private Boolean ekuCritical;
  private Boolean bcCritical;
  private List<KeyUsageType> keyUsages;
  private Boolean keyUsageCritical;

  /**
   * Get instance of default certificate profile configuration data for sign services
   *
   * @return default certificate profile configuration
   */
  public static CertificateProfileConfiguration getDefaultConfiguration() {
    return getBuilderWithDefaultValues().build();
  }

  /**
   * Get instance of certificate profile configuration data builder for sign services with default values
   *
   * @return certificate profile configuration data builder with default values
   */
  public static CertificateProfileConfiguration.CertificateProfileConfigurationBuilder getBuilderWithDefaultValues() {
    return CertificateProfileConfiguration.builder()
      .policy(Collections.emptyList())
      .policyCritical(false)
      .eku(Collections.emptyList())
      .ekuCritical(false)
      .bcCritical(false)
      .keyUsages(List.of(KeyUsageType.sign, KeyUsageType.nr));
  }

  public enum KeyUsageType{
    sign, encrypt, nr
  }

  public int getKeyUsageValue(PublicKey publicKey) {
    int keyUsageVal = 0;
    for (KeyUsageType keyUsageType : keyUsages) {
      switch (keyUsageType) {

      case sign:
        keyUsageVal += KeyUsage.digitalSignature;
        break;
      case encrypt:
        int encryptVal = publicKey instanceof RSAPublicKey ? KeyUsage.keyEncipherment : KeyUsage.keyAgreement;
        keyUsageVal += encryptVal;
        break;
      case nr:
        keyUsageVal += KeyUsage.nonRepudiation;
        break;
      }
    }
    return keyUsageVal;
  }

}

