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

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.annotation.Nonnull;

import org.apache.commons.lang.StringUtils;
import org.opensaml.saml.ext.saml2mdui.Logo;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Organization;

import lombok.Data;
import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.opensaml.saml2.metadata.build.AttributeConsumingServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ContactPersonBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.LogoBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.OrganizationBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.RequestedAttributeBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.UIInfoBuilder;

/**
 * Configuration class for a SP's SAML metadata.
 */
@Data
public class MetadataConfiguration {

  /**
   * A template for building metadata.
   */
  private EntityDescriptor template;

  /**
   * The entity categories to include in the metadata extension.
   */
  private List<String> entityCategories;

  /**
   * Configuration for the UIInfo extension.
   */
  private UIInfoConfig uiInfo;

  /**
   * Configuration for the Organization element.
   */
  private OrganizationConfig organization;

  /**
   * Configuration for the ContactPerson elements.
   */
  private Map<ContactPersonTypeEnumeration, ContactPersonConfig> contactPersons;

  /**
   * Requested attributes.
   */
  private List<RequestedAttributeConfig> requestedAttributes;

  /**
   * Service names (for AttributeConsumingServiceBuilder).
   */
  private List<LocalizedString> serviceNames;

  /**
   * Gets the {@code AttributeConsumingService} metadata element.
   *
   * @return the AttributeConsumingService element
   */
  public AttributeConsumingService createAttributeConsumingServiceElement() {
    if ((this.serviceNames == null || this.serviceNames.isEmpty())
        && (this.requestedAttributes == null || this.requestedAttributes.isEmpty())) {
      return null;
    }
    final AttributeConsumingServiceBuilder builder = AttributeConsumingServiceBuilder.builder();

    builder.serviceNames(this.serviceNames);

    if (this.requestedAttributes != null) {
      builder.requestedAttributes(this.requestedAttributes.stream()
        .filter(ra -> ra.getName() != null)
        .map(ra -> RequestedAttributeBuilder.builder(ra.getName()).isRequired(ra.isRequired()).build())
        .collect(Collectors.toList()));
    }

    return builder.build();
  }

  /**
   * Configuration class for UIInfo.
   */
  @Data
  public static class UIInfoConfig {
    /**
     * The UIInfo display names. Given as "country-code"-"text".
     */
    private List<LocalizedString> displayNames;

    /**
     * The UIInfo descriptions. Given as "country-code"-"text".
     */
    private List<LocalizedString> descriptions;

    /**
     * The UIInfo logotypes.
     */
    private List<UIInfoLogo> logos;

    /**
     * The privacy statement URLs. Given as "country-code"-"text".
     */
    private List<LocalizedString> privacyStatementsUrls;

    /**
     * Information URLs. Given as "country-code"-"text".
     */
    private List<LocalizedString> informationUrls;

    /**
     * Builds a {@link UIInfo} element.
     *
     * @param baseUrl the system base URL
     * @return a UIInfo element
     */
    public UIInfo toElement(final String baseUrl) {
      final List<Logo> logos = this.getLogos() != null
          ? this.getLogos().stream()
              .map(logo -> LogoBuilder.logo(String.format("%s%s", baseUrl, logo.getPath()),
                  logo.getHeight(), logo.getWidth()))
              .collect(Collectors.toList())
          : null;

      return UIInfoBuilder.builder()
          .displayNames(this.getDisplayNames())
          .descriptions(this.getDescriptions())
          .logos(logos)
          .privacyStatementURLs(this.getPrivacyStatementsUrls())
          .informationURLs(this.getInformationUrls())
          .build();
    }

    /**
     * Configuration class for the Logo element of the UIInfo element.
     */
    @Data
    public static class UIInfoLogo {

      /**
       * The logotype path (minus baseUri but including the context path).
       */
      private String path;

      /**
       * The logotype height (in pixels).
       */
      private Integer height;

      /**
       * The logotype width (in pixels).
       */
      private Integer width;
    }
  }

  /**
   * Configuration class for the Organization element.
   */
  @Data
  public static class OrganizationConfig {

    /**
     * The organization names. Given as "country-code"-"text".
     */
    private List<LocalizedString> names;

    /**
     * The organization display names. Given as "country-code"-"text".
     */
    private List<LocalizedString> displayNames;

    /**
     * The organization URL:s.
     */
    private List<LocalizedString> urls;

    /**
     * Builds an {@link Organization} element.
     *
     * @return an Organization element
     */
    public Organization toElement() {
      return OrganizationBuilder.builder()
          .organizationNames(this.getNames())
          .organizationDisplayNames(this.getDisplayNames())
          .organizationURLs(this.getUrls())
          .build();
    }
  }

  /**
   * Configuration class for the ContactPerson element.
   */
  @Data
  public static class ContactPersonConfig {
    /**
     * The company.
     */
    private String company;

    /**
     * Given name.
     */
    private String givenName;

    /**
     * Surname.
     */
    private String surname;

    /**
     * Email address.
     */
    private String emailAddress;

    /**
     * Telephone number.
     */
    private String telephoneNumber;

    /**
     * Builds a {@link ContactPerson} element.
     *
     * @param type the type
     * @return a ContactPerson element
     */
    public ContactPerson toElement(@Nonnull final ContactPersonTypeEnumeration type) {
      final ContactPersonBuilder b = ContactPersonBuilder.builder()
          .type(type)
          .company(this.getCompany())
          .givenName(this.getGivenName())
          .surname(this.getSurname());
      if (StringUtils.isNotBlank(this.getEmailAddress())) {
        b.emailAddresses(this.getEmailAddress());
      }
      if (StringUtils.isNotBlank(this.getTelephoneNumber())) {
        b.telephoneNumbers(this.getTelephoneNumber());
      }
      return b.build();
    }
  }

  /**
   * Configuration class for requested attributes.
   */
  @Data
  public static class RequestedAttributeConfig {

    /**
     * The attribute name.
     */
    private String name;

    /**
     * Required?
     */
    private boolean required;

  }
}
