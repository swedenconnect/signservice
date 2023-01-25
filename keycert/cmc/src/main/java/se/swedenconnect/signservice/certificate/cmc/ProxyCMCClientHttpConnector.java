/*
 * Copyright 2023 Sweden Connect
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
package se.swedenconnect.signservice.certificate.cmc;

import java.io.IOException;
import java.net.Proxy;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;

import javax.annotation.Nullable;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.TrustManager;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.entity.ByteArrayEntity;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import net.shibboleth.utilities.java.support.httpclient.HttpClientSupport;
import net.shibboleth.utilities.java.support.httpclient.TLSSocketFactoryBuilder;
import se.swedenconnect.ca.cmc.api.client.CMCClientHttpConnector;
import se.swedenconnect.ca.cmc.api.client.CMCHttpResponseData;
import se.swedenconnect.signservice.certificate.cmc.config.CMCKeyAndCertificateHandlerConfiguration;

/**
 * CMC client HTTP Connector providing Poxy with authentication settings through configuration
 */
@Slf4j
public class ProxyCMCClientHttpConnector implements CMCClientHttpConnector {

  /** MIME type for CMC request content type */
  private static final String CMC_MIME_TYPE = "application/pkcs7-mime";

  /** HttpClient for CMC requests */
  private HttpClient httpClient;

  /**
   * Constructor
   *
   * @param cmcClientProxyConfig CMC client proxy configuration
   */
  public ProxyCMCClientHttpConnector(final @Nullable CMCKeyAndCertificateHandlerConfiguration.HttpProxyConfiguration cmcClientProxyConfig) {
    this.httpClient = createHttpClient(cmcClientProxyConfig);
  }

  /** {@inheritDoc} */
  @Override public CMCHttpResponseData sendCmcRequest(final byte[] cmcRequestBytes, final URL requestUrl,
    final int connectTimeout, final int readTimeout) {

    HttpPost request;
    try {
      request = new HttpPost(requestUrl.toURI());
      request.addHeader("Content-Type", CMC_MIME_TYPE);
      request.setEntity(new ByteArrayEntity(cmcRequestBytes));
      request.setConfig(RequestConfig.custom()
          .setConnectTimeout(connectTimeout)
          .setConnectionRequestTimeout(connectTimeout)
          .setSocketTimeout(readTimeout)
        .build());
    }
    catch (URISyntaxException e) {
      throw new IllegalArgumentException("Bad URL syntax for CMC request");
    }

    try {
      HttpResponse httpResponse = httpClient.execute(request);
      byte[] responseData = IOUtils.toByteArray(httpResponse.getEntity().getContent());
      return CMCHttpResponseData.builder()
        .data(responseData)
        .exception(null)
        .responseCode(httpResponse.getStatusLine().getStatusCode())
        .build();
    }
    catch (IOException ex) {
      log.debug("Error receiving http data stream {}", ex.toString());
      return CMCHttpResponseData.builder()
        .data(null)
        .exception(ex)
        .responseCode(500)
        .build();
    }
  }

  /**
   * This function is not allowed for this implementation as Proxy settings are handled by the constructor.
   *
   * @param proxy proxy
   */
  @Override public void setProxy(Proxy proxy) {
    throw new IllegalArgumentException("Unsupported operation - This implementation use HTTPClient to provide proxy");
  }

  /**
   * Creates a HTTP client to use.
   *
   * @return a HttpClient
   */
  protected HttpClient createHttpClient(CMCKeyAndCertificateHandlerConfiguration.HttpProxyConfiguration cmcClientProxyConfig) {
    try {
      final List<TrustManager> managers = List.of(HttpClientSupport.buildNoTrustX509TrustManager());
      final HostnameVerifier hnv = new DefaultHostnameVerifier();

      HttpClientBuilder builder = new HttpClientBuilder();
      builder.setUseSystemProperties(true);
      if (cmcClientProxyConfig != null && cmcClientProxyConfig.getHost() != null) {
        builder.setConnectionProxyHost(cmcClientProxyConfig.getHost());
        builder.setConnectionProxyPort(cmcClientProxyConfig.getPort());
        if (StringUtils.isNotBlank(cmcClientProxyConfig.getUserName())) {
          builder.setConnectionProxyUsername(cmcClientProxyConfig.getUserName());
        }
        if (StringUtils.isNotBlank(cmcClientProxyConfig.getPassword())) {
          builder.setConnectionProxyPassword(cmcClientProxyConfig.getPassword());
        }
      }
      builder.setTLSSocketFactory(new TLSSocketFactoryBuilder()
        .setHostnameVerifier(hnv)
        .setTrustManagers(managers)
        .build());
      return builder.buildClient();
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to initialize HttpClient", e);
    }
  }
}
