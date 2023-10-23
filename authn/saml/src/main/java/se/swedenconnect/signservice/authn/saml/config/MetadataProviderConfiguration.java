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
package se.swedenconnect.signservice.authn.saml.config;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.TrustManager;

import org.apache.commons.lang3.StringUtils;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.httpclient.HttpClientBuilder;
import net.shibboleth.shared.httpclient.HttpClientSupport;
import net.shibboleth.shared.httpclient.TLSSocketFactoryBuilder;
import net.shibboleth.shared.resolver.ResolverException;
import se.swedenconnect.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.CompositeMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.MDQMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;

/**
 * Configuration class for metadata providers.
 */
@Slf4j
@Data
public class MetadataProviderConfiguration {

  /**
   * The certificate used to validate the metadata.
   */
  @Nullable
  private X509Certificate validationCertificate;

  /**
   * The URL from where metadata is downloaded. Mutually exclusive with {@code file}.
   */
  @Nullable
  private String url;

  /**
   * Optional property. If {@code url} is assigned, this setting points to a backup file where the downloaded data
   * should be saved.
   * <p>
   * If the {@code mdq} flag has been set, this property should point to a directory and not a file.
   * </p>
   */
  @Nullable
  private String backupLocation;

  /**
   * A path to locally stored metadata. Mutually exclusive with {@code url}.
   */
  @Nullable
  private String file;

  /**
   * If a metadata URL has been configured, setting this flag means that the metadata MDQ
   * (https://www.ietf.org/id/draft-young-md-query-17.html) protocol is used. The default is not to use MDQ.
   */
  @Nullable
  private Boolean mdq;

  /**
   * If the service is placed behind a HTTP proxy, this setting configures the proxy.
   */
  @Nullable
  private HttpProxyConfiguration httpProxy;

  /**
   * Additional providers.
   */
  @Nullable
  private List<MetadataProviderConfiguration> additional;

  /**
   * Configuration properties for an HTTP proxy.
   */
  @Data
  public static class HttpProxyConfiguration {

    /**
     * The proxy host.
     */
    @Nonnull
    private String host;

    /**
     * The proxy port.
     */
    private int port;

    /**
     * The proxy password (optional).
     */
    @Nullable
    private String password;

    /**
     * The proxy user name (optional).
     */
    @Nullable
    private String userName;
  }

  /**
   * Based on the configuration a {@link MetadataProvider} is created.
   *
   * @return a MetadataProvider
   */
  @Nonnull
  public MetadataProvider create() throws IllegalArgumentException {
    try {
      if (StringUtils.isNotBlank(this.url) && StringUtils.isNotBlank(this.file)) {
        throw new IllegalArgumentException("Illegal metadata provider configuration - Both url and file are set");
      }
      AbstractMetadataProvider provider = null;
      if (StringUtils.isNotBlank(this.url)) {
        if (this.mdq == null || !this.mdq.booleanValue()) {
          provider = new HTTPMetadataProvider(this.url, this.preProcessBackupFile(this.backupLocation),
              this.createHttpClient());
        }
        else {
          provider = new MDQMetadataProvider(this.url, this.createHttpClient(),
              this.preProcessBackupDirectory(this.backupLocation));
        }
        if (this.validationCertificate == null) {
          log.warn("No validation certificate given for metadata provider ({}) - metadata can not be trusted",
              this.url);
        }
      }
      else if (StringUtils.isNotBlank(this.file)) {
        provider = new FilesystemMetadataProvider(new File(this.file));
      }
      else {
        throw new IllegalArgumentException("Illegal metadata provider configuration - url or file must be set");
      }
      provider.setPerformSchemaValidation(false);
      provider.initialize();

      if (this.additional != null && !this.additional.isEmpty()) {
        final List<MetadataProvider> metadataProviders = new ArrayList<>();
        metadataProviders.add(provider);
        for (final MetadataProviderConfiguration mpc : this.additional) {
          metadataProviders.add(mpc.create());
        }
        final CompositeMetadataProvider compositeProvider =
            new CompositeMetadataProvider("composite-provider", metadataProviders);
        compositeProvider.initialize();
        return compositeProvider;
      }
      else {
        return provider;
      }
    }
    catch (final ResolverException | ComponentInitializationException e) {
      throw new IllegalArgumentException("Failed to initialize metadata provider - " + e.getMessage(), e);
    }
  }

  /**
   * Creates a HTTP client to use.
   *
   * @return a HttpClient
   */
  protected HttpClient createHttpClient() {
    try {
      final List<TrustManager> managers = Arrays.asList(HttpClientSupport.buildNoTrustX509TrustManager());
      final HostnameVerifier hnv = new DefaultHostnameVerifier();

      HttpClientBuilder builder = new HttpClientBuilder();
      builder.setUseSystemProperties(true);
      if (this.getHttpProxy() != null && this.getHttpProxy().getHost() != null) {
        builder.setConnectionProxyHost(this.getHttpProxy().getHost());
        builder.setConnectionProxyPort(this.getHttpProxy().getPort());
        if (StringUtils.isNotBlank(this.getHttpProxy().getUserName())) {
          builder.setConnectionProxyUsername(this.getHttpProxy().getUserName());
        }
        if (StringUtils.isNotBlank(this.getHttpProxy().getPassword())) {
          builder.setConnectionProxyPassword(this.getHttpProxy().getPassword());
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

  /**
   * Makes sure that all parent directories for the supplied file exists and returns the backup file as an absolute
   * path.
   *
   * @param backupFile the backup file
   * @return the absolute path of the backup file
   */
  @Nullable
  private String preProcessBackupFile(@Nullable final String backupFile) {
    if (backupFile == null) {
      return null;
    }
    final File b = new File(backupFile);
    this.preProcessBackupDirectory(b.getParentFile().getAbsolutePath());
    return b.getAbsolutePath();
  }

  /**
   * Makes sure that all parent directories exists and returns the directory as an absolute path.
   *
   * @param backupDirectory the backup directory
   * @return the absolute path of the backup directory
   */
  @Nullable
  private String preProcessBackupDirectory(@Nullable final String backupDirectory) {
    if (backupDirectory == null) {
      return null;
    }
    try {
      final Path path = Paths.get(backupDirectory);
      Files.createDirectories(path);
      return path.toFile().getAbsolutePath();
    }
    catch (final IOException e) {
      throw new IllegalArgumentException("Invalid backup-location");
    }
  }

}
