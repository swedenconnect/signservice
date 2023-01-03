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
package se.swedenconnect.signservice.authn.saml.config;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.commons.lang.StringUtils;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
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
   * Optional property. If {@code url} is assigned, this setting tells where a backup of the downloaded data should be
   * saved.
   * <p>
   * If the {@code mdq} flag has been set, this property should point to a directory and not a file.
   * </p>
   */
  @Nullable
  private String backupFile;

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
   * Additional providers.
   */
  @Nullable
  private List<MetadataProviderConfiguration> additional;

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
          provider = new HTTPMetadataProvider(this.url, this.backupFile,
              HTTPMetadataProvider.createDefaultHttpClient(null /* trust all */, new DefaultHostnameVerifier()));
        }
        else {
          provider = new MDQMetadataProvider(this.url,
              HTTPMetadataProvider.createDefaultHttpClient(null /* trust all */, new DefaultHostnameVerifier()),
              this.backupFile);
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

}
