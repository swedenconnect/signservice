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

import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import lombok.Getter;

/**
 * URL configuration settings for a SAML SP.
 */
public class SpUrlConfiguration {

  /**
   * The application base URL. Must not end with a slash. The base URL consists of the protocol, host and context path.
   */
  @Getter
  private String baseUrl;

  /**
   * The path to where the SP receives SAML responses. Relative to {@code baseUrl}.
   */
  @Getter
  private String assertionConsumerPath;

  /**
   * Optional additional path for receiving SAML responses. Relative to {@code baseUrl}. May be useful when testing and
   * debugging.
   */
  @Getter
  private String additionalAssertionConsumerPath;

  /**
   * The path to where the SP exposes its metadata. Relative to {@code baseUrl}.
   */
  @Getter
  private String metadataPublishingPath;

  /**
   * Assigns the application base URL. Must not end with a slash.
   *
   * @param baseUrl the application base URL
   */
  public void setBaseUrl(@Nonnull final String baseUrl) {
    this.baseUrl = Objects.requireNonNull(baseUrl, "baseUrl must not be null");
    if (this.baseUrl.endsWith("/")) {
      throw new IllegalArgumentException("The baseUrl must not end with a '/'");
    }
  }

  /**
   * Assigns the path to where the SP receives SAML responses. Relative to {@code baseUrl}.
   *
   * @param assertionConsumerPath the path for receiving SAML responses
   */
  public void setAssertionConsumerPath(@Nonnull final String assertionConsumerPath) {
    this.assertionConsumerPath =
        Objects.requireNonNull(assertionConsumerPath, "assertionConsumerPath must not be null");
    if (!this.assertionConsumerPath.startsWith("/")) {
      throw new IllegalArgumentException("The assertionConsumerPath must begin with a '/'");
    }
  }

  /**
   * Assigns an additional path for receiving SAML responses. Relative to {@code baseUrl}. May be useful when testing
   * and debugging.
   *
   * @param additionalAssertionConsumerPath additional path for receiving SAML responses
   */
  public void setAdditionalAssertionConsumerPath(@Nullable final String additionalAssertionConsumerPath) {
    this.additionalAssertionConsumerPath = additionalAssertionConsumerPath;
    if (this.additionalAssertionConsumerPath != null && !this.additionalAssertionConsumerPath.startsWith("/")) {
      throw new IllegalArgumentException("The additionalAssertionConsumerPath must begin with a '/'");
    }
  }

  /**
   * Assigns the path to where the SP exposes its metadata. Relative to {@code baseUrl}.
   *
   * @param metadataPublishingPath the metadata publishing path
   */
  public void setMetadataPublishingPath(@Nonnull final String metadataPublishingPath) {
    this.metadataPublishingPath =
        Objects.requireNonNull(metadataPublishingPath, "metadataPublishingPath must not be null");
    if (!this.metadataPublishingPath.startsWith("/")) {
      throw new IllegalArgumentException("The metadataPublishingPath must begin with a '/'");
    }
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    StringBuffer sb = new StringBuffer("base-url='")
        .append(this.baseUrl)
        .append("', assertion-consumer-path='")
        .append(this.assertionConsumerPath);
    if (this.additionalAssertionConsumerPath != null) {
      sb.append("', additional-assertion-consumer-path='")
          .append(this.additionalAssertionConsumerPath);
    }
    sb.append("', metadata-publishing-path='")
        .append(this.metadataPublishingPath)
        .append("'");
    return sb.toString();
  }

}
