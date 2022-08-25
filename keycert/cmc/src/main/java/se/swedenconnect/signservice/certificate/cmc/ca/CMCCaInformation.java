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
package se.swedenconnect.signservice.certificate.cmc.ca;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Collectors;

import lombok.Builder;
import lombok.Data;
import se.swedenconnect.ca.cmc.model.admin.response.StaticCAInformation;

/**
 * A wrapper around {@link StaticCAInformation} for easier usage.
 */
@Data
@Builder
public class CMCCaInformation {

  /** The CA certificate chain */
  private List<X509Certificate> certificateChain;

  /**
   * The optional OCSP certificate used by the OCSP responder of the CA.
   */
  private X509Certificate ocspCertificate;

  /**
   * The location(s) of the CRL of the CA service.
   */
  private List<String> crlDpUrls;

  /**
   * The URL to the OCSP responder of this CA (if present).
   */
  private String ocspResponserUrl;

  /**
   * The algorithm used by this CA to sign certificates.
   */
  private String caAlgorithm;

  public StaticCAInformation toStaticCAInformation() {
    final StaticCAInformation info = new StaticCAInformation();
    if (this.certificateChain != null) {
      info.setCertificateChain(this.certificateChain.stream()
          .map(c -> {
            try {
              return c.getEncoded();
            }
            catch (final CertificateEncodingException e) {
              throw new SecurityException("Invalid certificate encoding", e);
            }
          })
          .collect(Collectors.toList()));
    }
    if (this.ocspCertificate != null) {
      try {
        info.setOcspCertificate(this.ocspCertificate.getEncoded());
      }
      catch (final CertificateEncodingException e) {
        throw new SecurityException("Invalid certificate encoding", e);
      }
    }
    info.setCrlDpURLs(this.crlDpUrls);
    info.setOcspResponserUrl(this.ocspResponserUrl);
    info.setCaAlgorithm(this.caAlgorithm);
    return info;
  }

}
