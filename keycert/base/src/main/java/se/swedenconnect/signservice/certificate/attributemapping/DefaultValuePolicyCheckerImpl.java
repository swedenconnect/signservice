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
package se.swedenconnect.signservice.certificate.attributemapping;

import java.util.List;
import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.commons.lang.StringUtils;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.swedenconnect.signservice.certificate.CertificateAttributeType;

/**
 * Default implementation of the {@link DefaultValuePolicyChecker} interface.
 */
public class DefaultValuePolicyCheckerImpl implements DefaultValuePolicyChecker {

  /** Holds the configuration. */
  private List<DefaultValuePolicyCheckerConfig> config;

  /**
   * If no configuration exists for a supplied item (attribute type and reference), we reply with a default (true or
   * false).
   */
  private boolean defaultReply;

  /**
   * Constructor.
   *
   * @param config the configuration telling which attributes to handle
   * @param defaultReply whether we should allow or disallow queries for attributes that we don't have configuration for
   */
  public DefaultValuePolicyCheckerImpl(
      @Nullable final List<DefaultValuePolicyCheckerConfig> config, final boolean defaultReply) {
    this.config = config;
    this.defaultReply = defaultReply;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isDefaultValueAllowed(
      @Nonnull final CertificateAttributeType attributeType, @Nonnull final String ref, @Nonnull final String value) {

    if (attributeType == null || ref == null || StringUtils.isBlank(ref) || value == null
        || StringUtils.isBlank(value)) {
      throw new IllegalArgumentException("Invalid input");
    }

    if (this.config == null) {
      return this.defaultReply;
    }

    final DefaultValuePolicyCheckerConfig entry = this.config.stream()
        .filter(c -> Objects.equals(c.getAttributeType(), attributeType))
        .filter(c -> Objects.equals(c.getRef(), ref))
        .findFirst()
        .orElse(null);

    if (entry == null) {
      return this.defaultReply;
    }
    if (entry.getAllowedValues() == null || entry.getAllowedValues().isEmpty()) {
      return entry.isAllowAnyValue();
    }
    return entry.getAllowedValues().stream().anyMatch(v -> v.equalsIgnoreCase(value));
  }

  /**
   * Configuration data for the default value policy checker.
   */
  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class DefaultValuePolicyCheckerConfig {

    /**
     * The type of certificate attribute or subject alt name.
     */
    private CertificateAttributeType attributeType;

    /**
     * The reference of the certificate attribute or subject alt name.
     */
    private String ref;

    /**
     * A list of allowed values. If null or empty, the allowAnyValue will determine if the value is OK.
     */
    private List<String> allowedValues;

    /**
     * If allowedValues are null or empty, this field determines whether a default value assignment should be allowed.
     */
    @Builder.Default
    private boolean allowAnyValue = false;
  }

}
