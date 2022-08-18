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

import java.security.cert.X509Certificate;

import javax.annotation.Nullable;

import lombok.Getter;
import lombok.Setter;

/**
 * Configuration class for metadata providers.
 */
public class MetadataProviderConfiguration {

  /**
   * The certificate used to validate the metadata.
   */
  @Getter
  @Setter
  @Nullable
  private X509Certificate validationCertificate;

  /**
   * The URL from where metadata is downloaded. Mutually exclusive with {@code file}.
   */
  @Getter
  @Setter
  @Nullable
  private String url;

  /**
   * Optional property. If {@code url} is assigned, this setting tells where a backup of the downloaded data should be
   * saved.
   */
  @Getter
  @Setter
  @Nullable
  private String backupFile;

  /**
   * A path to locally stored metadata. Mutually exclusive with {@code url}.
   */
  @Getter
  @Setter
  @Nullable
  private String file;

}
