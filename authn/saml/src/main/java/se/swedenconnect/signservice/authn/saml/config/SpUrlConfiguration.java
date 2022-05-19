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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import lombok.Getter;
import lombok.Setter;

/**
 * URL configuration settings for a SAML SP.
 */
public class SpUrlConfiguration {

  /**
   * The application base URL. Must not end with a slash.
   *
   * @param baseUrl the application base URL
   * @return the application base URL
   */
  @Getter
  @Setter
  @Nonnull
  private String baseUrl;

  /**
   * The path to where the SP receives SAML responses. Relative to {@code baseUrl}.
   *
   * @param assertionConsumerPath the path for receiving SAML responses
   * @return the path for receiving SAML responses
   */
  @Getter
  @Setter
  @Nonnull
  private String assertionConsumerPath;

  /**
   * Optional additional path for receiving SAML responses. Relative to {@code baseUrl}. May be useful when testing and
   * debugging.
   *
   * @param additionalAssertionConsumerPath additional path for receiving SAML responses
   * @return additional path for receiving SAML responses
   */
  @Getter
  @Setter
  @Nullable
  private String additionalAssertionConsumerPath;

  /**
   * The path to where the SP exposes its metadata. Relative to {@code baseUrl}.
   *
   * @param metadataPublishingPath the metadata publishing path
   * @return the metadata publishing path
   */
  @Getter
  @Setter
  @Nonnull
  private String metadataPublishingPath;

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format(
        "base-url='%s', assertion-consumerpath='%s', additional-assertion-consumer-path='%s', metadata-publishing-path='%s'",
        this.baseUrl, this.assertionConsumerPath, this.additionalAssertionConsumerPath, this.metadataPublishingPath);
  }

}
