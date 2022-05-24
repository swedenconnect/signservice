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
package se.swedenconnect.signservice.certificate.simple;

import lombok.NonNull;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import se.idsec.signservice.security.certificate.CertificateUtils;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeModel;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.data.SAMLAuthContextBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.CertificatePolicyModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.SubjDirectoryAttributesModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.AttributeMapping;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.ObjectFactory;
import se.swedenconnect.schemas.saml_2_0.assertion.Attribute;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.certificate.CertificateAttributeType;
import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.certificate.base.AbstractKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.base.attributemapping.AttributeMappingData;
import se.swedenconnect.signservice.certificate.base.attributemapping.AttributeMappingException;
import se.swedenconnect.signservice.certificate.base.attributemapping.DefaultValuePolicy;
import se.swedenconnect.signservice.certificate.base.attributemapping.impl.DefaultSAMLAttributeMapper;
import se.swedenconnect.signservice.certificate.base.configuration.DefaultConfiguration;
import se.swedenconnect.signservice.certificate.base.keyprovider.SignServiceSigningKeyProvider;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.session.SignServiceContext;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * A simple key and certificate handler.
 */
@Slf4j
public class SimpleKeyAndCertificateHandler extends AbstractKeyAndCertificateHandler {

  /** CA service used to issue certificates */
  private CAService caService;
  /** name of this certificate handler */
  private String name;
  /** Attribute mapper mapping attribute data from assertion to Certificates */
  AttributeMapper attributeMapper;

  /**
   * Optional certificate policy to be included in issued certificates.
   *
   * @param certificate policy to be included in issued certificates
   */
  @Setter private CertificatePolicyModel certificatePolicy;

  @Setter private String serviceName = "sign-service";

  /**
   * Constructor for the key and certificate handler
   *
   * @param signingKeyProvider provider for providing signing keys
   * @param defaultConfiguration
   * @param algorithmRegistry
   */
  public SimpleKeyAndCertificateHandler(
    final @NonNull SignServiceSigningKeyProvider signingKeyProvider,
    final @NonNull DefaultConfiguration defaultConfiguration,
    final @NonNull AlgorithmRegistry algorithmRegistry, final @NonNull CAService caService,
    final @NonNull AttributeMapper attributeMapper,
    final @NonNull String name) {
    super(signingKeyProvider, defaultConfiguration, algorithmRegistry);
    this.caService = caService;
    this.attributeMapper = attributeMapper;
    this.name = name;
  }

  /** {@inheritDoc} */
  @Override public String getName() {
    return this.name;
  }

  /** {@inheritDoc} */
  @Override protected void specificRequirementTests(SignRequestMessage signRequest,
    SignServiceContext context) throws InvalidRequestException {
    // No additional tests
  }

  /** {@inheritDoc} */
  @Override protected X509Certificate obtainSigningCertificate(@NonNull KeyPair signingKeyPair,
    @NonNull SignRequestMessage signRequest, @NonNull IdentityAssertion assertion,
    SignServiceContext context) throws CertificateException {

    log.debug("Issuing certificate from internal CA");
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
      log.debug("Get mapping data from configured attribute mapper {}", attributeMapper.getClass());
      mappedCertAttributes = attributeMapper.getMappedCertAttributes(signRequest, assertion);
    }
    catch (AttributeMappingException e) {
      log.debug("Attribute mapping failed: {}", e.toString());
      throw new CertificateException("Attribute mapping failed");
    }

    log.debug("Creating certificate model");
    // Get certificate subject name
    CertNameModel<?> certNameModel = getCertNameModel(mappedCertAttributes);
    // Get the certificate model builder
    DefaultCertificateModelBuilder certificateModelBuilder = (DefaultCertificateModelBuilder) caService.getCertificateModelBuilder(
      certNameModel,
      signingKeyPair.getPublic());

    // Obtain attribute mapping for the AuthContextExtension
    List<AttributeMapping> attributeMappings = getAuthContextExtAttributeMappings(mappedCertAttributes);
    // Add AuthContextExtension
    certificateModelBuilder
      .authenticationContext(SAMLAuthContextBuilder.instance()
        .serviceID(serviceName)
        .assertionRef(assertion.getIdentifier())
        .authnContextClassRef(assertion.getAuthnContext().getIdentifier())
        .authenticationInstant(new Date(assertion.getAuthnInstant().toEpochMilli()))
        .identityProvider(assertion.getIssuer())
        .attributeMappings(attributeMappings)
        .build());

    // Add policy if available
    if (certificatePolicy != null) {
      certificateModelBuilder.certificatePolicy(certificatePolicy);
      log.debug("Adding certificate policy {}", certificatePolicy.toString());
    }

    // Add Subject Alt Name if present
    addSANToCertModel(certificateModelBuilder, mappedCertAttributes);
    // Add Subject Directory Attributes if present
    addSubjDirAttributesToCertModel(certificateModelBuilder, mappedCertAttributes);

    // Issue certificate
    log.debug("Issuing certificate from certificate model");
    X509CertificateHolder certificateHolder = caService.issueCertificate(certificateModelBuilder.build());
    try {
      // Return X509 Certificate
      return CertificateUtils.decodeCertificate(certificateHolder.getEncoded());
    }
    catch (IOException e) {
      log.error("Failed to encode X509Certificate from X509CertificateModel", e);
      throw new CertificateException(e);
    }
  }

  private void addSubjDirAttributesToCertModel(DefaultCertificateModelBuilder certificateModelBuilder, List<AttributeMappingData> mappedCertAttributes)
    throws CertificateException {
    List<AttributeModel> sanAttributeList = new ArrayList<>();
    for (AttributeMappingData mappedAttribute : mappedCertAttributes) {
      if (mappedAttribute.getCertificateAttributeType().equals(CertificateAttributeType.SDA)){
        try {
          sanAttributeList.add(AttributeModel.builder()
              .attributeType(new ASN1ObjectIdentifier(mappedAttribute.getReference()))
              .valueList(List.of(mappedAttribute.getValue()))
            .build());
        } catch (Exception ex) {
          throw new CertificateException("Illegal Subject Directory Attribute attribute data - aborting certificate issuance");
        }
      }
    }
    if (!sanAttributeList.isEmpty()){
      certificateModelBuilder.subjectDirectoryAttributes(new SubjDirectoryAttributesModel(sanAttributeList));
    }
  }

  private void addSANToCertModel(DefaultCertificateModelBuilder certificateModelBuilder, List<AttributeMappingData> mappedCertAttributes)
    throws CertificateException {
    Map<Integer, String> subjectAltNameMap = new HashMap<>();
    for (AttributeMappingData mappedAttribute : mappedCertAttributes) {
      if (mappedAttribute.getCertificateAttributeType().equals(CertificateAttributeType.SAN)){
        try {
          subjectAltNameMap.put(Integer.valueOf(mappedAttribute.getReference()), mappedAttribute.getValue());
        } catch (Exception ex) {
          throw new CertificateException("Illegal SAN attribute data - aborting certificate issuance");
        }
      }
    }
    if (!subjectAltNameMap.isEmpty()){
      certificateModelBuilder.subjectAltNames(subjectAltNameMap);
    }
  }

  private List<AttributeMapping> getAuthContextExtAttributeMappings(List<AttributeMappingData> mappedCertAttributes) {
    List<AttributeMapping> extAttrMappingList = new ArrayList<>();
    for (AttributeMappingData attributeMappingData : mappedCertAttributes) {
      ObjectFactory objectFactory = new ObjectFactory();
      AttributeMapping attributeMapping = objectFactory.createAttributeMapping();
      attributeMapping.setRef(attributeMappingData.getReference());
      attributeMapping.setType(attributeMappingData.getCertificateAttributeType().getType());
      se.swedenconnect.schemas.saml_2_0.assertion.ObjectFactory samlObjFactory = new se.swedenconnect.schemas.saml_2_0.assertion.ObjectFactory();
      Attribute attribute = samlObjFactory.createAttribute();
      attribute.setName(attributeMappingData.getSourceId());
      attribute.setFriendlyName(attributeMappingData.getSourceFriendlyName());
      attribute.getAttributeValues().add(attributeMappingData.getValue());
      attributeMapping.setAttribute(attribute);
      extAttrMappingList.add(attributeMapping);
    }
    return extAttrMappingList;
  }

  private CertNameModel<?> getCertNameModel(List<AttributeMappingData> attributeMappings) throws CertificateException {
    List<AttributeTypeAndValueModel> attributeList = new ArrayList<>();
    for (AttributeMappingData attributeMapping : attributeMappings) {
      CertificateAttributeType attributeType = attributeMapping.getCertificateAttributeType();
      if (attributeType.equals(CertificateAttributeType.RDN)) {
        try {
          attributeList.add(AttributeTypeAndValueModel.builder()
            .attributeType(new ASN1ObjectIdentifier(attributeMapping.getReference()))
            .value(attributeMapping.getValue())
            .build()
          );
        } catch (Exception ex) {
          throw new CertificateException("Certificate attribute from authentication contains illegal data - aborting certificate issuance");
        }
      }
    }
    return new ExplicitCertNameModel(attributeList);
  }

  /** {@inheritDoc} */
  @Override protected void isCertificateTypeSupported(@NonNull CertificateType certificateType,
    String certificateProfile) throws InvalidRequestException {
    if (!certificateType.equals(CertificateType.PKC)) {
      throw new InvalidRequestException(
        "This simple key and certificate handler can only produce non qualified certificates");
    }
  }
}
