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

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.cmc.api.CMCCaApi;
import se.swedenconnect.ca.cmc.api.CMCRequestParser;
import se.swedenconnect.ca.cmc.api.CMCResponseParser;
import se.swedenconnect.ca.cmc.api.client.CMCClientHttpConnector;
import se.swedenconnect.ca.cmc.api.client.CMCHttpResponseData;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;

import java.io.IOException;
import java.net.URL;

/**
 * Http connector for CMC tests. This connector will skip using HTTP to a CMC responder and instead
 * obtain the CMC response directly from a test CA
 */
@Slf4j
public class TestCMCHttpConnector implements CMCClientHttpConnector {

  private final CMCCaApi cmcCaApi;
  CMCResponseParser cmcResponseParser;

  static {
  }

  public TestCMCHttpConnector(CMCCaApi cmcCaApi) {
    this.cmcCaApi = cmcCaApi;
  }

  /** {@inheritDoc} */
  @Override public CMCHttpResponseData sendCmcRequest(final byte[] cmcRequestBytes, final URL requestUrl, final int connectTimeout, final int readTimeout) {

    CMCRequest cmcRequest;
    try {
      cmcRequest = CMCApiFactory.getCmcRequestParser().parseCMCrequest(cmcRequestBytes);
      log.debug("Sending CMC request from test CMC connector:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, false, true));
    }
    catch (IOException e) {
      e.printStackTrace();
    }
    CMCResponse cmcResponse = cmcCaApi.processRequest(cmcRequestBytes);
    log.debug("Obtained CMC response from CA:\n{}", CMCDataPrint.printCMCResponse(cmcResponse, false));
    return new CMCHttpResponseData(cmcResponse.getCmcResponseBytes(), 200, null);
  }
}
