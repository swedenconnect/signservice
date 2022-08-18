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

package se.swedenconnect.signservice.certificate.cmc;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import se.swedenconnect.ca.cmc.api.CMCCertificateModelBuilder;
import se.swedenconnect.ca.cmc.api.client.CMCClient;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeModel;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.data.SAMLAuthContextBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.CertificatePolicyModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.SubjDirectoryAttributesModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.AttributeMapping;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.ObjectFactory;
import se.swedenconnect.schemas.saml_2_0.assertion.Attribute;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.certificate.CertificateAttributeType;
import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.certificate.base.AbstractKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.base.attributemapping.AttributeMappingData;
import se.swedenconnect.signservice.certificate.base.attributemapping.AttributeMappingException;
import se.swedenconnect.signservice.certificate.base.configuration.DefaultConfiguration;
import se.swedenconnect.signservice.certificate.base.keyprovider.SignServiceSigningKeyProvider;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.session.SignServiceContext;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * CMC based key and certificate handler obtaining certificates from a remote CA using CMC
 */
@Slf4j
public class CMCKeyAndCertificateHandler extends AbstractKeyAndCertificateHandler {

  /** CMC Client for remote CA service used to issue certificates */
  private final CMCClient cmcClient;

  /** Attribute mapper mapping attribute data from assertion to Certificates */
  private final AttributeMapper attributeMapper;

  /**
   * Optional certificate policy to be included in issued certificates.
   *
   * @param certificatePolicy policy to be included in issued certificates
   */
  @Setter
  private CertificatePolicyModel certificatePolicy;

  /**
   * The certificate type produced by this certificate handler. Default PKC certificates
   */
  @Setter
  private CertificateType supportedCertificateType;

  /**
   * Constructor for the key and certificate handler.
   *
   * @param signingKeyProvider provider for providing signing keys
   * @param defaultConfiguration default value configuration data
   * @param algorithmRegistry algorithm registry
   * @param cmcClient CMC client used to issue certificates using CMC
   * @param attributeMapper mapper for mapping authentication attributes to certificate attributes
   */
  public CMCKeyAndCertificateHandler(
    final @Nonnull SignServiceSigningKeyProvider signingKeyProvider,
    final @Nonnull DefaultConfiguration defaultConfiguration,
    final @Nonnull AlgorithmRegistry algorithmRegistry,
    final @Nonnull CMCClient cmcClient,
    final @Nonnull AttributeMapper attributeMapper) {
    super(signingKeyProvider, defaultConfiguration, algorithmRegistry);
    this.supportedCertificateType = CertificateType.PKC;
    this.cmcClient = Objects.requireNonNull(cmcClient, "CMC client must not be null");
    this.attributeMapper = Objects.requireNonNull(attributeMapper, "attributeMapper must not be null");
  }

  /** {@inheritDoc} */
  @Override
  protected void specificRequirementTests(final @Nonnull SignRequestMessage signRequest,
    final @Nonnull SignServiceContext context) throws InvalidRequestException {
    // No additional tests
  }

  /** {@inheritDoc} */
  @Override
  protected X509Certificate obtainSigningCertificate(final @Nonnull PkiCredential signingKeyPair,
    final @Nonnull SignRequestMessage signRequest, final @Nonnull IdentityAssertion assertion,
    final @Nonnull SignServiceContext context) throws CertificateException {

    log.debug("Issuing certificate from CA via CMC ...");

    // Test basic availability of essential data
    if (assertion.getIdentifier() == null) {
      throw new CertificateException("Assertion identifier must not be null");
    }
    if (assertion.getAuthnContext() == null || assertion.getAuthnContext().getIdentifier() == null) {
      throw new CertificateException("Assertion authentication LoA identifier must not be null");
    }
    if (assertion.getIssuer() == null) {
      throw new CertificateException("Assertion issuer must not be null");
    }

    List<AttributeMappingData> mappedCertAttributes;
    try {
      log.debug("Get mapping data from configured attribute mapper {}", this.attributeMapper.getClass());
      mappedCertAttributes = this.attributeMapper.getMappedCertAttributes(signRequest, assertion);
    }
    catch (final AttributeMappingException e) {
      log.debug("Attribute mapping failed: {}", e.toString());
      throw new CertificateException("Attribute mapping failed", e);
    }

    log.debug("Creating certificate model");
    // Get certificate subject name
    final CertNameModel<?> certNameModel = this.getCertNameModel(mappedCertAttributes);
    // Get the certificate model builder
    final CMCCertificateModelBuilder certificateModelBuilder;
    try {
      certificateModelBuilder = this.cmcClient.getCertificateModelBuilder(
        signingKeyPair.getPublicKey(),
        certNameModel, true, true
      );
    }
    catch (IOException e) {
      throw new CertificateException("Error obtaining certificate model from CMC client", e);
    }

    // Obtain attribute mapping for the AuthContextExtension
    final List<AttributeMapping> attributeMappings = this.getAuthContextExtAttributeMappings(mappedCertAttributes);
    // Add AuthContextExtension
    certificateModelBuilder
      .authenticationContext(SAMLAuthContextBuilder.instance()
        .serviceID(this.serviceName == null ? signRequest.getClientId() : this.serviceName)
        .assertionRef(assertion.getIdentifier())
        .authnContextClassRef(assertion.getAuthnContext().getIdentifier())
        .authenticationInstant(new Date(assertion.getAuthnInstant().toEpochMilli()))
        .identityProvider(assertion.getIssuer())
        .attributeMappings(attributeMappings)
        .build());

    // Add policy if available
    if (this.certificatePolicy != null) {
      certificateModelBuilder.certificatePolicy(this.certificatePolicy);
      log.debug("Adding certificate policy {}", this.certificatePolicy.toString());
    }

    // Add Subject Alt Name if present
    this.addSANToCertModel(certificateModelBuilder, mappedCertAttributes);
    // Add Subject Directory Attributes if present
    this.addSubjDirAttributesToCertModel(certificateModelBuilder, mappedCertAttributes);

    // Issue certificate
    log.debug("Issuing certificate from certificate model");

    try {
      CMCResponse cmcResponse = this.cmcClient.issueCertificate(certificateModelBuilder.build());
      final CMCResponseStatus responseStatus = cmcResponse.getResponseStatus();
      if (!responseStatus.getStatus().equals(CMCStatusType.success)) {
        final CMCFailType failType = responseStatus.getFailType();
        final String failTypeMessage =
          responseStatus.getMessage() != null ? ", Message: " + responseStatus.getMessage() : "";
        String message =
          "Status: " + responseStatus.getStatus().name() + ", Failtype: " + failType.name() + failTypeMessage;
        log.debug("Failed to issue requested certificate: {}", message);
        throw new CertificateException(message);
      }
      return cmcResponse.getReturnCertificates().get(0);
    }
    catch (final IOException e) {
      final String msg = "Failed to complete CMC request";
      log.info("Failed to complete CMC request to issue certificate: {}", e.getMessage());
      throw new CertificateException(msg, e);
    }
  }

  /**
   * Add subject directory attributes to the certificate model.
   *
   * @param certificateModelBuilder certificate model builder
   * @param mappedCertAttributes mapped attributes from authentication source with mapping information
   * @throws CertificateException on error processing subject directory attribute data
   */
  private void addSubjDirAttributesToCertModel(final CMCCertificateModelBuilder certificateModelBuilder,
    final List<AttributeMappingData> mappedCertAttributes)
    throws CertificateException {
    final List<AttributeModel> sanAttributeList = new ArrayList<>();
    for (final AttributeMappingData mappedAttribute : mappedCertAttributes) {
      if (mappedAttribute.getCertificateAttributeType().equals(CertificateAttributeType.SDA)) {
        try {
          sanAttributeList.add(AttributeModel.builder()
            .attributeType(new ASN1ObjectIdentifier(mappedAttribute.getReference()))
            .valueList(List.of(mappedAttribute.getValue()))
            .build());
        }
        catch (final Exception ex) {
          throw new CertificateException(
            "Illegal Subject Directory Attribute attribute data - aborting certificate issuance");
        }
      }
    }
    if (!sanAttributeList.isEmpty()) {
      // Subject dir attribute was found. Add it.
      certificateModelBuilder.subjectDirectoryAttributes(new SubjDirectoryAttributesModel(sanAttributeList));
    }
  }

  /**
   * Add subject alternative name to certificate model.
   *
   * @param certificateModelBuilder certificate model builder
   * @param mappedCertAttributes mapped attributes from authentication source with mapping information
   * @throws CertificateException error parsing subject alt name data
   */
  private void addSANToCertModel(final CMCCertificateModelBuilder certificateModelBuilder,
    final List<AttributeMappingData> mappedCertAttributes)
    throws CertificateException {
    final Map<Integer, String> subjectAltNameMap = new HashMap<>();
    for (final AttributeMappingData mappedAttribute : mappedCertAttributes) {
      if (mappedAttribute.getCertificateAttributeType().equals(CertificateAttributeType.SAN)) {
        try {
          subjectAltNameMap.put(Integer.valueOf(mappedAttribute.getReference()), mappedAttribute.getValue());
        }
        catch (final Exception ex) {
          throw new CertificateException("Illegal SAN attribute data - aborting certificate issuance", ex);
        }
      }
    }
    if (!subjectAltNameMap.isEmpty()) {
      certificateModelBuilder.subjectAltNames(subjectAltNameMap);
    }
  }

  /**
   * Get attribute mapping data for the AuthnContextExtension
   *
   * @param mappedCertAttributes mapped attributes from authentication source with mapping information
   * @return attribute mapping data for the AuthnContextExtension
   */
  private List<AttributeMapping> getAuthContextExtAttributeMappings(
    final List<AttributeMappingData> mappedCertAttributes) {
    final List<AttributeMapping> extAttrMappingList = new ArrayList<>();
    for (final AttributeMappingData attributeMappingData : mappedCertAttributes) {
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
   * Get subject name model
   *
   * @param mappedCertAttributes mapped attributes from authentication source with mapping information
   * @return subject name model
   * @throws CertificateException error parsing subject name information
   */
  private CertNameModel<?> getCertNameModel(final List<AttributeMappingData> mappedCertAttributes)
    throws CertificateException {
    final List<AttributeTypeAndValueModel> attributeList = new ArrayList<>();
    for (final AttributeMappingData attributeMapping : mappedCertAttributes) {
      final CertificateAttributeType attributeType = attributeMapping.getCertificateAttributeType();
      if (attributeType.equals(CertificateAttributeType.RDN)) {
        try {
          attributeList.add(AttributeTypeAndValueModel.builder()
            .attributeType(new ASN1ObjectIdentifier(attributeMapping.getReference()))
            .value(attributeMapping.getValue())
            .build());
        }
        catch (final Exception ex) {
          throw new CertificateException(
            "Certificate attribute from authentication contains illegal data - aborting certificate issuance", ex);
        }
      }
    }
    return new ExplicitCertNameModel(attributeList);
  }

  /** {@inheritDoc} */
  @Override
  protected void isCertificateTypeSupported(@Nonnull CertificateType certificateType,
    @Nullable String certificateProfile) throws InvalidRequestException {
    if (!supportedCertificateType.equals(certificateType)) {
      throw new InvalidRequestException(
        "This CMC key and certificate handler can only produce certificates of type " + supportedCertificateType);
    }
  }
}
