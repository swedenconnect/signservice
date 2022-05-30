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
package se.swedenconnect.signservice.certificate.base.attributemapping.impl;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.commons.lang.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.certificate.base.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.base.attributemapping.AttributeMappingData;
import se.swedenconnect.signservice.certificate.base.attributemapping.AttributeMappingException;
import se.swedenconnect.signservice.certificate.base.attributemapping.DefaultValuePolicy;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.attribute.IdentityAttributeIdentifier;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.msg.CertificateAttributeMapping;
import se.swedenconnect.signservice.protocol.msg.RequestedCertificateAttribute;
import se.swedenconnect.signservice.protocol.msg.SigningCertificateRequirements;

/**
 * Default implementation for an attribute mapper based on SAML authentication.
 */
@Slf4j
public class DefaultSAMLAttributeMapper implements AttributeMapper {

  /** Policy to validate if default values in sign request are acceptable for inclusion in certificates. */
  private final DefaultValuePolicy defaultValuePolicy;

  /**
   * Constructor.
   *
   * @param defaultValuePolicy default value policy to test if default values from sign request are acceptable
   */
  public DefaultSAMLAttributeMapper(@Nonnull final DefaultValuePolicy defaultValuePolicy) {
    this.defaultValuePolicy = Objects.requireNonNull(defaultValuePolicy, "defaultValuePolicy must not be null");
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public List<AttributeMappingData> getMappedCertAttributes(@Nonnull final SignRequestMessage signRequest,
      @Nonnull final IdentityAssertion assertion) throws AttributeMappingException {

    final SigningCertificateRequirements certificateRequirements = Optional.ofNullable(
        signRequest.getSigningCertificateRequirements())
        .orElseThrow(() -> new AttributeMappingException("No certificate requirements in sign request"));

    final List<CertificateAttributeMapping> attributeMappingRequirements = Optional.ofNullable(
        certificateRequirements.getAttributeMappings())
        .orElseThrow(() -> new AttributeMappingException("No attribute mapping requirements in sign request"));

    final List<AttributeMappingData> attrMappingDataList = new ArrayList<>();
    for (final CertificateAttributeMapping mappingRequirement : attributeMappingRequirements) {
      final AttributeMappingData mappingData = this.getMappingData(mappingRequirement, assertion);
      // If there is a critical error
      if (mappingData != null) {
        attrMappingDataList.add(mappingData);
      }
    }

    // Return result
    return attrMappingDataList;
  }

  /**
   * Process an attribute mapping of a particular requested certificate attribute.
   *
   * @param mappingRequirement attribute mapping requirement for this attribute
   * @param assertion the assertion holding attribute data
   * @return attribute mapping data
   * @throws AttributeMappingException if a requirement for attribute data could not be served by the assertion
   */
  @Nullable
  private AttributeMappingData getMappingData(@Nonnull final CertificateAttributeMapping mappingRequirement,
      @Nonnull final IdentityAssertion assertion) throws AttributeMappingException {

    final RequestedCertificateAttribute requestedCertificateAttribute = Optional.ofNullable(
        mappingRequirement.getDestination())
        .orElseThrow(() -> new AttributeMappingException("Attribute mapping requirement lacks requirement data"));
    final List<IdentityAttributeIdentifier> sources = mappingRequirement.getSources();
    if (sources == null || sources.isEmpty()) {
      if (requestedCertificateAttribute.isRequired()) {
        throw new AttributeMappingException("Required attribute has no mapping sources in sign request");
      }
      log.info("Optional attribute has no defined sources - skipping attribute mapping for {}",
          requestedCertificateAttribute.getIdentifier());
      return null;
    }
    // We have source requirements. Se if we can find a matching source
    final IdentityAttribute<?> matchingAttribute =
        this.getMatchingAttribute(requestedCertificateAttribute, sources, assertion);
    if (matchingAttribute == null) {
      if (StringUtils.isNotBlank(requestedCertificateAttribute.getDefaultValue())) {
        final boolean defaultValueAllowed =
            this.defaultValuePolicy.isDefaultValueAllowed(requestedCertificateAttribute.getType(),
                requestedCertificateAttribute.getIdentifier(), requestedCertificateAttribute.getDefaultValue());
        if (defaultValueAllowed) {
          return AttributeMappingData.builder()
              .defaultValue(true)
              .certificateAttributeType(requestedCertificateAttribute.getType())
              .reference(requestedCertificateAttribute.getIdentifier())
              .sourceFriendlyName(requestedCertificateAttribute.getFriendlyName())
              .value(requestedCertificateAttribute.getDefaultValue())
              .build();
        }
      }
      // No matching attribute and no valid default value
      if (requestedCertificateAttribute.isRequired()) {
        throw new AttributeMappingException(
            "Required attribute " + requestedCertificateAttribute.getIdentifier() + " has no default value");
      }
      // No matching attribute, no default value but attribute not required. Skip.
      log.debug("Optional attribute {} could not be served", requestedCertificateAttribute.getIdentifier());
      return null;
    }
    final String valueStr = this.getStringValue(matchingAttribute);
    if (StringUtils.isBlank(valueStr)) {
      if (requestedCertificateAttribute.isRequired()) {
        throw new AttributeMappingException(
            "Null value in mapped attribute for required attribute: " + requestedCertificateAttribute.getIdentifier());
      }
      log.debug("Null value in mapped attribute for non-required attribute - skipping");
      return null;
    }
    // We have a matching attribute. Use it
    return AttributeMappingData.builder()
        .certificateAttributeType(requestedCertificateAttribute.getType())
        .reference(requestedCertificateAttribute.getIdentifier())
        .defaultValue(false)
        .sourceFriendlyName(matchingAttribute.getFriendlyName())
        .sourceId(matchingAttribute.getIdentifier())
        .value(valueStr)
        .build();
  }

  private String getStringValue(final IdentityAttribute<?> matchingAttribute) {
    final Object value = matchingAttribute.getValue();
    if (value instanceof String) {
      return (String) value;
    }
    if (value == null) {
      return null;
    }
    if (value instanceof Integer) {
      return String.valueOf(value);
    }
    return value.toString();
  }

  private IdentityAttribute<?> getMatchingAttribute(final RequestedCertificateAttribute requestedCertificateAttribute,
      final List<IdentityAttributeIdentifier> sources, final IdentityAssertion assertion) {

    final List<IdentityAttribute<?>> identityAttributes = assertion.getIdentityAttributes();
    if (identityAttributes == null || identityAttributes.isEmpty()) {
      return null;
    }

    for (final IdentityAttributeIdentifier sourceId : sources) {
      final String identifier = sourceId.getIdentifier();
      final Optional<IdentityAttribute<?>> matchAttributeOptional = identityAttributes.stream()
          .filter(identityAttribute -> identityAttribute.getIdentifier().equalsIgnoreCase(identifier))
          .findFirst();
      if (matchAttributeOptional.isPresent()) {
        // We found a match. use it
        return matchAttributeOptional.get();
      }
    }
    // We found no match
    return null;
  }
}
