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
package se.swedenconnect.signservice.certificate.base;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import se.swedenconnect.ca.engine.ca.models.cert.AttributeModel;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel.CertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.data.SAMLAuthContextBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.SubjDirectoryAttributesModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.AbstractCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.AttributeMapping;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.ObjectFactory;
import se.swedenconnect.schemas.saml_2_0.assertion.Attribute;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.authn.AuthnContextIdentifier;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.certificate.CertificateAttributeType;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMappingData;
import se.swedenconnect.signservice.certificate.keyprovider.KeyProvider;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.session.SignServiceContext;

/**
 * An abstract base class to be used by implementations that rely on the CA engine.
 */
public abstract class AbstractCaEngineKeyAndCertificateHandler extends AbstractKeyAndCertificateHandler {

  /**
   * Constructor. The algorithm registry will be set to {@link AlgorithmRegistrySingleton#getInstance()}.
   *
   * @param keyProviders a list of key providers that this handler uses
   * @param attributeMapper the attribute mapper
   */
  public AbstractCaEngineKeyAndCertificateHandler(
      @Nonnull final List<KeyProvider> keyProviders,
      @Nonnull final AttributeMapper attributeMapper) {
    super(keyProviders, attributeMapper);
  }

  /**
   * Constructor.
   *
   * @param keyProviders a list of key providers that this handler uses
   * @param attributeMapper the attribute mapper
   * @param algorithmRegistry algorithm registry
   */
  public AbstractCaEngineKeyAndCertificateHandler(
      @Nonnull final List<KeyProvider> keyProviders,
      @Nonnull final AttributeMapper attributeMapper,
      @Nonnull final AlgorithmRegistry algorithmRegistry) {
    super(keyProviders, attributeMapper, algorithmRegistry);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected X509Certificate issueSigningCertificate(
      @Nonnull final PkiCredential signingKeyPair, @Nonnull final SignRequestMessage signRequest,
      @Nonnull final IdentityAssertion assertion, @Nonnull final List<AttributeMappingData> certAttributes,
      @Nullable final String certificateProfile, @Nonnull final SignServiceContext context)
      throws CertificateException {

    // Test basic availability of essential data
    if (assertion.getIdentifier() == null) {
      throw new IllegalArgumentException("Assertion identifier must be set");
    }
    if (Optional.ofNullable(assertion.getAuthnContext()).map(AuthnContextIdentifier::getIdentifier).isEmpty()) {
      throw new IllegalArgumentException("Assertion authentication LoA identifier must be present");
    }
    if (assertion.getIssuer() == null) {
      throw new IllegalArgumentException("Assertion issuer must not be present");
    }
    if (assertion.getAuthnInstant() == null) {
      throw new IllegalArgumentException("Missing authentication instant from assertion");
    }

    // Get certificate subject name model.
    final CertNameModel<?> certificateNameModel = this.createCertificateNameModel(certAttributes);

    // Get the certificate model builder.
    final AbstractCertificateModelBuilder<? extends AbstractCertificateModelBuilder<?>> certificateModelBuilder =
        this.createCertificateModelBuilder(signingKeyPair.getPublicKey(), certificateNameModel);

    // Add the AuthContextExtension.
    certificateModelBuilder.authenticationContext(SAMLAuthContextBuilder.instance()
        .serviceID(Optional.ofNullable(this.getServiceName()).orElseGet(() -> signRequest.getClientId()))
        .assertionRef(assertion.getIdentifier())
        .authnContextClassRef(assertion.getAuthnContext().getIdentifier())
        .authenticationInstant(new Date(assertion.getAuthnInstant().toEpochMilli()))
        .identityProvider(assertion.getIssuer())
        .attributeMappings(this.getAuthContextExtAttributeMappings(certAttributes))
        .build());

    // Add Subject alternative names if present.
    final Map<Integer, String> subjectAltNames = this.getSubjectAltNames(certAttributes);
    if (subjectAltNames != null) {
      certificateModelBuilder.subjectAltNames(subjectAltNames);
    }

    // Add Subject Directory Attributes if present.
    final SubjDirectoryAttributesModel subjectDirectoryAttributes = this.getSubjectDirectoryAttributes(certAttributes);
    if (subjectDirectoryAttributes != null) {
      certificateModelBuilder.subjectDirectoryAttributes(subjectDirectoryAttributes);
    }

    return this.issueSigningCertificate(certificateModelBuilder.build(), certificateProfile, context);
  }

  /**
   * Issues the signing certificate based on the supplied certificate model.
   *
   * @param certificateModel the certificate model
   * @param certificateProfile the certificate profile (may be null)
   * @param context the SignService context
   * @return an X509Certificate
   * @throws CertificateException for issuance errors
   */
  @Nonnull
  protected abstract X509Certificate issueSigningCertificate(@Nonnull final CertificateModel certificateModel,
      @Nullable final String certificateProfile, @Nonnull final SignServiceContext context) throws CertificateException;

  /**
   * Creates a {@link CertificateModelBuilder} based on the supplied public key and certificate name model object.
   *
   * @param subjectPublicKey the public key
   * @param subject the certificate nane model object
   * @return a certificate model builder
   * @throws CertificateException for errors
   */
  @Nonnull
  protected abstract AbstractCertificateModelBuilder<? extends AbstractCertificateModelBuilder<?>> createCertificateModelBuilder(
      @Nonnull final PublicKey subjectPublicKey, @Nonnull final CertNameModel<?> subject) throws CertificateException;

  /**
   * Creates a subject name model based on the mapped certificate attributes.
   *
   * @param certAttributes mapped attributes from authentication source with mapping information
   * @return subject name model
   * @throws CertificateException error parsing subject name information
   */
  @Nonnull
  protected CertNameModel<?> createCertificateNameModel(final List<AttributeMappingData> certAttributes)
      throws CertificateException {
    final List<AttributeTypeAndValueModel> attributeList = new ArrayList<>();
    for (final AttributeMappingData attributeMapping : certAttributes) {
      if (CertificateAttributeType.RDN.equals(attributeMapping.getCertificateAttributeType())) {
        try {
          attributeList.add(AttributeTypeAndValueModel.builder()
              .attributeType(new ASN1ObjectIdentifier(attributeMapping.getReference()))
              .value(attributeMapping.getValue())
              .build());
        }
        catch (final Exception e) {
          throw new CertificateException(
              "Certificate attribute from authentication contains illegal data - aborting certificate issuance", e);
        }
      }
    }
    return new ExplicitCertNameModel(attributeList);
  }

  /**
   * Get attribute mapping data for the AuthnContextExtension.
   *
   * @param certAttributes mapped attributes from authentication source with mapping information
   * @return attribute mapping data for the AuthnContextExtension
   */
  @Nonnull
  protected List<AttributeMapping> getAuthContextExtAttributeMappings(
      @Nonnull final List<AttributeMappingData> certAttributes) {

    final List<AttributeMapping> extAttrMappingList = new ArrayList<>();
    for (final AttributeMappingData attributeMappingData : certAttributes) {
      final ObjectFactory objectFactory = new ObjectFactory();
      final AttributeMapping attributeMapping = objectFactory.createAttributeMapping();
      attributeMapping.setRef(attributeMappingData.getReference());
      attributeMapping.setType(attributeMappingData.getCertificateAttributeType().getType());
      final se.swedenconnect.schemas.saml_2_0.assertion.ObjectFactory samlObjFactory =
          new se.swedenconnect.schemas.saml_2_0.assertion.ObjectFactory();
      final Attribute attribute = samlObjFactory.createAttribute();
      attribute.setName(attributeMappingData.getSourceId());
      attribute.setFriendlyName(attributeMappingData.getSourceFriendlyName());
      attribute.getAttributeValues().add(attributeMappingData.getValue());
      attributeMapping.setAttribute(attribute);
      extAttrMappingList.add(attributeMapping);
    }
    return extAttrMappingList;
  }

  /**
   * Gets the subject alternative name to certificate model.
   *
   * @param certAttributes mapped attributes from authentication source with mapping information
   * @return a subject alternative names mapping, or null
   * @throws CertificateException error parsing subject alt name data
   */
  @Nullable
  protected Map<Integer, String> getSubjectAltNames(@Nonnull final List<AttributeMappingData> certAttributes)
      throws CertificateException {
    final Map<Integer, String> subjectAltNames = new HashMap<>();
    for (final AttributeMappingData mappedAttribute : certAttributes) {
      if (CertificateAttributeType.SAN.equals(mappedAttribute.getCertificateAttributeType())) {
        try {
          subjectAltNames.put(Integer.valueOf(mappedAttribute.getReference()), mappedAttribute.getValue());
        }
        catch (final Exception e) {
          throw new CertificateException("Illegal SAN attribute data - aborting certificate issuance", e);
        }
      }
    }
    return !subjectAltNames.isEmpty() ? subjectAltNames : null;
  }

  /**
   * Gets the subject directory attributes.
   *
   * @param certAttributes mapped attributes from authentication source with mapping information
   * @return a SubjDirectoryAttributesModel or null
   * @throws CertificateException on error processing subject directory attribute data
   */
  @Nullable
  protected SubjDirectoryAttributesModel getSubjectDirectoryAttributes(
      @Nonnull final List<AttributeMappingData> certAttributes)
      throws CertificateException {
    final List<AttributeModel> sanAttributes = new ArrayList<>();
    for (final AttributeMappingData mappedAttribute : certAttributes) {
      if (CertificateAttributeType.SDA.equals(mappedAttribute.getCertificateAttributeType())) {
        try {
          sanAttributes.add(AttributeModel.builder()
              .attributeType(new ASN1ObjectIdentifier(mappedAttribute.getReference()))
              .valueList(List.of(mappedAttribute.getValue()))
              .build());
        }
        catch (final Exception e) {
          throw new CertificateException(
              "Illegal Subject Directory Attribute attribute data - aborting certificate issuance", e);
        }
      }
    }
    return !sanAttributes.isEmpty() ? new SubjDirectoryAttributesModel(sanAttributes) : null;
  }

}