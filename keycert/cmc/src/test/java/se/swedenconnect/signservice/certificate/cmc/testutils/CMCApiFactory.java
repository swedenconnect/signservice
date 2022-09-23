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
package se.swedenconnect.signservice.certificate.cmc.testutils;

import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;

import lombok.Getter;
import se.swedenconnect.ca.cmc.api.CMCCaApi;
import se.swedenconnect.ca.cmc.api.CMCRequestParser;
import se.swedenconnect.ca.cmc.api.CMCResponseFactory;
import se.swedenconnect.ca.cmc.api.impl.DefaultCMCCaApi;
import se.swedenconnect.ca.cmc.auth.impl.DefaultCMCValidator;
import se.swedenconnect.ca.engine.ca.issuer.CAService;

/**
 * Factory for providing CMC API instances
 */
public class CMCApiFactory {

  static CMCResponseFactory cmcResponseFactory;
  @Getter static CMCRequestParser cmcRequestParser;

  static {
    try {
      CMCSigner caCmcSigner = new CMCSigner(
        new KeyPair(TestCredentials.publicCMCCaSignerECKey, TestCredentials.privateCMCCaSignerECKey),
        TestCredentials.cMCCaSignerCertificate);
      cmcResponseFactory = new CMCResponseFactory(caCmcSigner.getSignerChain(), caCmcSigner.getContentSigner());
      cmcRequestParser = new CMCRequestParser(new DefaultCMCValidator(TestCredentials.cMCClientSignerCertificate),
        cmsSignedData -> {});
    }
    catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  public static CMCCaApi getCMCApi(CAService ca) {
    return new DefaultCMCCaApi(ca, cmcRequestParser, cmcResponseFactory);
  }

  public static CMCCaApi getBadCMCApi(CAService ca) throws CertificateEncodingException {
    CMCRequestParser badCmcReqParser =  new CMCRequestParser(new DefaultCMCValidator(TestCredentials.cMCCaSignerCertificate), cmsSignedData -> {});
    return new DefaultCMCCaApi(ca, badCmcReqParser, cmcResponseFactory);
  }

}
