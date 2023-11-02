/*
 * Copyright 2022-2023 Sweden Connect
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
package se.swedenconnect.signservice.app.frontend;

import java.io.IOException;

import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.ssl.TrustStrategy;
import org.apache.tomcat.util.http.Rfc6265CookieProcessor;
import org.apache.tomcat.util.http.SameSiteCookies;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.embedded.tomcat.TomcatContextCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.CommonsRequestLoggingFilter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletResponse;

/**
 * SignService application front-end main class.
 */
@SpringBootApplication
public class SignServiceFrontend {

  /**
   * Program main.
   *
   * @param args program arguments
   */
  public static void main(final String[] args) {
    SpringApplication.run(SignServiceFrontend.class, args);
  }

  /**
   * Creates the {@link RestTemplate} that we use when communicating with the SignService backend.
   *
   * @return a RestTemplate
   */
  @Bean
  RestTemplate restTemplate() {
    try {
      // For this example we trust all SSL/TLS certs. DO NOT COPY AND USE IN PRODUCTION!
      //
      final TrustStrategy acceptingTrustStrategy = (cert, authType) -> true;
      final SSLContext sslContext = SSLContexts.custom()
          .loadTrustMaterial(null, acceptingTrustStrategy)
          .build();
      final SSLConnectionSocketFactory sslsf =
          new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
      final Registry<ConnectionSocketFactory> socketFactoryRegistry =
          RegistryBuilder.<ConnectionSocketFactory> create()
              .register("https", sslsf)
              .register("http", new PlainConnectionSocketFactory())
              .build();

      final BasicHttpClientConnectionManager connectionManager =
          new BasicHttpClientConnectionManager(socketFactoryRegistry);
      final CloseableHttpClient httpClient = HttpClients.custom()
          .setConnectionManager(connectionManager)
          .disableRedirectHandling()
          .build();

      final HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
      requestFactory.setHttpClient(httpClient);

      final RestTemplate restTemplate = new RestTemplate(requestFactory);
      return restTemplate;
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to configure restTemplate", e);
    }
  }

  /**
   * Configures the same site cookie ...
   */
  @Configuration
  public static class WebMvcConfig implements WebMvcConfigurer {

    @Bean
    TomcatContextCustomizer sameSiteCookiesConfig() {
      return context -> {
        final Rfc6265CookieProcessor cookieProcessor = new Rfc6265CookieProcessor();
        cookieProcessor.setSameSiteCookies(SameSiteCookies.NONE.getValue());
        context.setCookieProcessor(cookieProcessor);
      };
    }
  }

  /**
   * Creates a CommonsRequestLoggingFilter bean.
   * Turn on logging using: {@code org.springframework.web.filter.CommonsRequestLoggingFilter: DEBUG}.
   * @return a CommonsRequestLoggingFilter
   */
  @Bean
  CommonsRequestLoggingFilter requestLoggingFilter() {
    final CommonsRequestLoggingFilter loggingFilter = new CommonsRequestLoggingFilter();
    loggingFilter.setIncludeClientInfo(true);
    loggingFilter.setIncludeQueryString(true);
    loggingFilter.setIncludePayload(true);
    loggingFilter.setMaxPayloadLength(64000);
    return loggingFilter;
  }

  /**
   * Make sure nothing is cached.
   */
  @WebFilter("/sign/*")
  public class AddResponseHeaderFilter implements Filter {

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
        throws IOException, ServletException {
      final HttpServletResponse httpServletResponse = (HttpServletResponse) response;
      httpServletResponse.setHeader("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
      chain.doFilter(request, response);
    }

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void destroy() {
    }
  }

}
