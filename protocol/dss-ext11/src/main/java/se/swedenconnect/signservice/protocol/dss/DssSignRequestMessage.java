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
package se.swedenconnect.signservice.protocol.dss;

import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.annotation.Nonnull;
import javax.xml.bind.JAXBException;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.lang3.StringUtils;
import org.apache.xml.security.Init;
import org.w3c.dom.Document;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.sign.xml.XMLMessageSignatureValidator;
import se.idsec.signservice.security.sign.xml.XMLSignatureLocation;
import se.idsec.signservice.security.sign.xml.XMLSignatureLocation.ChildPosition;
import se.idsec.signservice.security.sign.xml.impl.DefaultXMLMessageSignatureValidator;
import se.idsec.signservice.utils.ProtocolVersion;
import se.idsec.signservice.xml.DOMUtils;
import se.idsec.signservice.xml.JAXBMarshaller;
import se.swedenconnect.schemas.csig.dssext_1_1.CertRequestProperties;
import se.swedenconnect.schemas.csig.dssext_1_1.MappedAttributeType;
import se.swedenconnect.schemas.csig.dssext_1_1.PreferredSAMLAttributeNameType;
import se.swedenconnect.schemas.csig.dssext_1_1.SignRequestExtension;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTasks;
import se.swedenconnect.schemas.dss_1_0.SignRequest;
import se.swedenconnect.schemas.saml_2_0.assertion.Attribute;
import se.swedenconnect.schemas.saml_2_0.assertion.AttributeStatement;
import se.swedenconnect.schemas.saml_2_0.assertion.AudienceRestriction;
import se.swedenconnect.schemas.saml_2_0.assertion.Conditions;
import se.swedenconnect.schemas.saml_2_0.assertion.NameIDType;
import se.swedenconnect.signservice.authn.impl.SimpleAuthnContextIdentifier;
import se.swedenconnect.signservice.certificate.CertificateAttributeType;
import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.core.attribute.AttributeException;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.attribute.IdentityAttributeIdentifier;
import se.swedenconnect.signservice.core.attribute.impl.DefaultIdentityAttributeIdentifier;
import se.swedenconnect.signservice.protocol.ProtocolException;
import se.swedenconnect.signservice.protocol.ProtocolProcessingRequirements;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.dss.jaxb.JaxbAttributeConverter;
import se.swedenconnect.signservice.protocol.msg.AuthnRequirements;
import se.swedenconnect.signservice.protocol.msg.CertificateAttributeMapping;
import se.swedenconnect.signservice.protocol.msg.MessageConditions;
import se.swedenconnect.signservice.protocol.msg.SignMessage;
import se.swedenconnect.signservice.protocol.msg.SignatureRequirements;
import se.swedenconnect.signservice.protocol.msg.SigningCertificateRequirements;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultAuthnRequirements;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultCertificateAttributeMapping;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultMessageConditions;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultRequestedCertificateAttribute;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultSignatureRequirements;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultSigningCertificateRequirements;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;
import se.swedenconnect.signservice.signature.impl.DefaultAdESObject;
import se.swedenconnect.signservice.signature.impl.DefaultRequestedSignatureTask;

/**
 * An implementation of the {@link SignRequestMessage} interface for sign request messages according to <a href=
 * "https://docs.swedenconnect.se/technical-framework/latest/09_-_DSS_Extension_for_Federated_Signing_Services.html">DSS
 * Extension for Federated Central Signing Services</a>.
 */
@Slf4j
class DssSignRequestMessage implements SignRequestMessage {

  /** For serializing. */
  private static final long serialVersionUID = -5875475186053392826L;

  /** Processing requirements. */
  private static final ProtocolProcessingRequirements processingRequirements = new DssProtocolProcessingRequirements();

  /** Where to find the XML signatures. */
  private static XMLSignatureLocation xmlSignatureLocation;

  /** For validating signatures on SignResponse messages. */
  private static final XMLMessageSignatureValidator signatureValidator = new DefaultXMLMessageSignatureValidator();

  /** Maximum supported version. */
  private static ProtocolVersion MAX_VERSION = ProtocolVersion.valueOf("1.4");

  /** Minimum supported version. */
  private static ProtocolVersion MIN_VERSION = ProtocolVersion.valueOf("1.1");

  /** The attribute converter that converts between JAXB and the generic attribute representation. */
  private static JaxbAttributeConverter attributeConverter = new JaxbAttributeConverter();

  static {
    try {
      xmlSignatureLocation = new XMLSignatureLocation("/*/*[local-name()='OptionalInputs']", ChildPosition.LAST);
    }
    catch (final XPathExpressionException e) {
      throw new RuntimeException(e);
    }

    // The certificate validator requires that xmlsec has been initialized ...
    if (!Init.isInitialized()) {
      Init.init();
    }
  }

  /** The contained SignRequest. */
  private final SignRequestWrapper signRequest;

  /** The XML document for the SignRequest. */
  private transient Document xml;

  /**
   * Constructor setting the SignRequest message that we handle.
   *
   * @param signRequest the sign request message
   * @param xml the XML document for the message
   */
  public DssSignRequestMessage(final SignRequest signRequest, final Document xml) {
    this.signRequest = new SignRequestWrapper(signRequest);
    this.xml = xml;
  }

  /** {@inheritDoc} */
  @Override
  public ProtocolProcessingRequirements getProcessingRequirements() {
    return processingRequirements;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSigned() {
    try {
      return Optional.ofNullable(xmlSignatureLocation.getSignature(this.getXml())).isPresent();
    }
    catch (final XPathExpressionException e) {
      log.info("Failure checking whether signature is present in SignRequest message", e);
      return false;
    }
  }

  /** {@inheritDoc} */
  @Override
  public void verifySignature(final List<X509Certificate> certificates) throws SignatureException {
    signatureValidator.validate(this.getXml(), certificates, xmlSignatureLocation);
  }

  /**
   * Asserts that the message is correct given the specifications <a href=
   * "https://docs.swedenconnect.se/technical-framework/latest/09_-_DSS_Extension_for_Federated_Signing_Services.html">DSS
   * Extension for Federated Central Signing Services</a> and <a href=
   * "https://docs.swedenconnect.se/technical-framework/latest/07_-_Implementation_Profile_for_using_DSS_in_Central_Signing_Services.html">Implementation
   * Profile for using OASIS DSS in Central Signing Services</a>
   *
   * @throws ProtocolException for protocol errors
   */
  public void assertCorrectMessage() throws ProtocolException {

    // RequestID
    //
    if (!this.signRequest.isSetRequestID()) {
      final String msg = "No RequestID in SignRequest message - this is required";
      log.info("{}", msg);
      throw new ProtocolException(msg);
    }

    // Profile attribute
    //
    if (!this.signRequest.isSetProfile()) {
      log.info("Missing Profile attribute in request - assuming {} [request-id: '{}']",
          DssConstants.DSS_PROFILE, this.signRequest.getRequestID());
    }
    else if (!DssConstants.DSS_PROFILE.equals(this.signRequest.getProfile())) {
      final String msg = String.format("Unsupported Profile attribute (%s) - expected %s",
          this.signRequest.getProfile(), DssConstants.DSS_PROFILE);
      log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
      throw new ProtocolException(msg);
    }

    // SignTasks ...
    //
    try {
      final List<RequestedSignatureTask> signTasks = this.getSignatureTasks();
      if (signTasks.isEmpty()) {
        final String msg = "Missing SignTasks - at least one SignTaskData is required";
        log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
        throw new ProtocolException(msg);
      }
      for (final RequestedSignatureTask st : signTasks) {
        if (st.getTaskId() == null && signTasks.size() > 1) {
          final String msg = "Missing SignTaskId - this ID is required if more than one SignTaskData is set";
          log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
          throw new ProtocolException(msg);
        }
        if (st.getSignatureType() == null) {
          final String msg = "Missing SigType - this field is required";
          log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
          throw new ProtocolException(msg);
        }
        if (st.getTbsData() == null) {
          final String msg = "Missing ToBeSignedBytes - this element is required";
          log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
          throw new ProtocolException(msg);
        }
      }
    }
    catch (final DssProtocolException e) {
      throw new ProtocolException(e.getMessage(), e);
    }

    // SignRequestExtension
    //
    final SignRequestExtension extension = this.signRequest.getSignRequestExtension();
    if (extension == null) {
      final String msg = "SignRequestExtension is missing or incorrectly encoded";
      log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
      throw new ProtocolException(msg);
    }

    // Version
    //
    try {
      final ProtocolVersion version = this.getVersion();
      if (version.compareTo(MIN_VERSION) < 0) {
        final String msg = String.format("Version %s is less than what is supported (at least %s is required)",
            version, MIN_VERSION);
        log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
        throw new ProtocolException(msg);
      }
      if (version.compareTo(MAX_VERSION) > 0) {
        final String msg = String.format("Version %s is greater than what is supported (%s or lower is required)",
            version, MAX_VERSION);
        log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
        throw new ProtocolException(msg);
      }
    }
    catch (final IllegalArgumentException e) {
      final String msg = String.format("Illegal version %s", extension.getVersion());
      log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
      throw new ProtocolException(msg);
    }

    // RequestTime
    //
    if (this.getIssuedAt() == null) {
      final String msg = "RequestTime is missing - this field is required";
      log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
      throw new ProtocolException(msg);
    }

    // Conditions
    //
    final MessageConditions conditions = this.getConditions();
    if (conditions == null) {
      final String msg = "Conditions is missing - this element is required";
      log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
      throw new ProtocolException(msg);
    }
    else if (conditions.getNotBefore() == null) {
      final String msg = "Conditions.notBefore is missing - this field is required";
      log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
      throw new ProtocolException(msg);
    }
    else if (conditions.getNotAfter() == null) {
      final String msg = "Conditions.notOnOrAfter is missing - this field is required";
      log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
      throw new ProtocolException(msg);
    }
    if (this.getResponseUrl() == null) {
      final String msg = "Conditions.AudienceRestriction is missing - the response URL must be given here";
      log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
      throw new ProtocolException(msg);
    }

    // Signer is optional, but if it's there it must be correct ...
    //
    final AttributeStatement signer = extension.getSigner();
    if (signer != null && signer.isSetAttributesAndEncryptedAttributes()) {
      for (final Object object : signer.getAttributesAndEncryptedAttributes()) {
        if (Attribute.class.isInstance(object)) {
          try {
            // By converting, we check if the attributes given are correct ...
            attributeConverter.convert(Attribute.class.cast(object));
          }
          catch (final AttributeException e) {
            final String msg = String.format("Invalid attribute (%s) under Signer - %s",
                Attribute.class.cast(object).getName(), e.getMessage());
            log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
            throw new ProtocolException(msg, e);
          }
        }
      }
    }

    // IdentityProvider
    //
    final AuthnRequirements authnRequirements = this.getAuthnRequirements();
    if (authnRequirements == null || authnRequirements.getAuthnServiceID() == null) {
      final String msg = "IdentityProvider is missing - this field is required";
      log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
      throw new ProtocolException(msg);
    }

    // AuthnProfile
    //
    if (authnRequirements != null && authnRequirements.getAuthnProfile() != null) {
      // The profile states: "If this element is set, the Version attribute of the SignRequestExtension element MUST be
      // set to "1.4" or higher. Implementations prior to version 1.4 of this specification do not support the element."
      //
      // But it really doesn't matter so we just issue a log entry noting this...
      //
      if (this.getVersion().compareTo(ProtocolVersion.valueOf("1.4")) < 0) {
        log.info("Invalid use of AuthnProfile - requires version 1.4 higher, but version is {} [request-id: '{}']",
            this.getVersion(), this.signRequest.getRequestID());
      }
    }

    // SignRequester
    //
    if (this.getClientId() == null) {
      final String msg = "SignRequester is missing - this field is required";
      log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
      throw new ProtocolException(msg);
    }

    // SignService
    //
    if (this.getSignServiceId() == null) {
      final String msg = "SignService is missing - this field is required";
      log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
      throw new ProtocolException(msg);
    }

    // RequestedSignatureAlgorithm
    //
    try {
      this.getSignatureRequirements();
    }
    catch (final DssProtocolException e) {
      log.info("{} [request-id: '{}']", e.getMessage(), this.signRequest.getRequestID());
      throw new ProtocolException(e.getMessage());
    }

    // SignMessage is optional ...
    //
    if (extension.getSignMessage() != null) {
      final se.swedenconnect.schemas.csig.dssext_1_1.SignMessage signMessage = extension.getSignMessage();
      if (signMessage.getMessage() == null && signMessage.getEncryptedMessage() == null) {
        final String msg = "Bad SignMessage provided - either Message or EncryptedMessage must be assigned";
        log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
        throw new ProtocolException(msg);
      }
    }

    // CertRequestProperties
    //
    if (extension.getCertRequestProperties() != null) {
      try {
        this.getSigningCertificateRequirements();
      }
      catch (final Exception e) {
        final String msg = String.format("Error checking CertRequestProperties - %s", e.getMessage());
        log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
        throw new ProtocolException(msg, e);
      }
    }

  }

  /** {@inheritDoc} */
  @Override
  public String getRelayState() {
    return this.getRequestId();
  }

  /** {@inheritDoc} */
  @Override
  public String getRequestId() {
    return this.signRequest.getRequestID();
  }

  /**
   * Gets the version field of the SignRequest.
   *
   * @return the version
   */
  public ProtocolVersion getVersion() {
    return Optional.ofNullable(this.signRequest.getSignRequestExtension())
        .map(SignRequestExtension::getVersion)
        .map(ProtocolVersion::valueOf)
        .orElse(ProtocolVersion.valueOf("1.1"));
  }

  /** {@inheritDoc} */
  @Override
  public Instant getIssuedAt() {
    return Optional.ofNullable(this.signRequest.getSignRequestExtension())
        .map(SignRequestExtension::getRequestTime)
        .map(XMLGregorianCalendar::toGregorianCalendar)
        .map(GregorianCalendar::toInstant)
        .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  public String getClientId() {
    return Optional.ofNullable(this.signRequest.getSignRequestExtension())
        .map(SignRequestExtension::getSignRequester)
        .map(NameIDType::getValue)
        .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  public String getResponseUrl() {
    return Optional.ofNullable(this.signRequest.getSignRequestExtension())
        .map(SignRequestExtension::getConditions)
        .map(Conditions::getConditionsAndAudienceRestrictionsAndOneTimeUses)
        .get()
        .stream()
        .filter(AudienceRestriction.class::isInstance)
        .map(AudienceRestriction.class::cast)
        .filter(AudienceRestriction::isSetAudiences)
        .map(AudienceRestriction::getAudiences)
        .map(a -> a.get(0))
        .findFirst()
        .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  public String getSignServiceId() {
    return Optional.ofNullable(this.signRequest.getSignRequestExtension())
        .map(SignRequestExtension::getSignService)
        .map(NameIDType::getValue)
        .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  public MessageConditions getConditions() {
    final Conditions conditions = Optional.ofNullable(this.signRequest.getSignRequestExtension())
        .map(SignRequestExtension::getConditions)
        .orElse(null);

    final Instant notBefore = Optional.ofNullable(conditions)
        .map(Conditions::getNotBefore)
        .map(XMLGregorianCalendar::toGregorianCalendar)
        .map(GregorianCalendar::toInstant)
        .orElse(null);

    final Instant notAfter = Optional.ofNullable(conditions)
        .map(Conditions::getNotOnOrAfter)
        .map(XMLGregorianCalendar::toGregorianCalendar)
        .map(GregorianCalendar::toInstant)
        .orElse(null);

    if (notBefore != null || notAfter != null) {
      return new DefaultMessageConditions(notBefore, notAfter);
    }
    else {
      return null;
    }
  }

  /** {@inheritDoc} */
  @Override
  public AuthnRequirements getAuthnRequirements() {
    final DefaultAuthnRequirements authnRequirements = new DefaultAuthnRequirements();
    final SignRequestExtension extension = this.signRequest.getSignRequestExtension();
    if (extension == null) {
      return null;
    }
    authnRequirements.setAuthnProfile(extension.getAuthnProfile());
    authnRequirements.setAuthnServiceID(Optional.ofNullable(extension.getIdentityProvider())
        .map(NameIDType::getValue)
        .orElse(null));

    final CertRequestProperties certRequestProperties = extension.getCertRequestProperties();
    if (certRequestProperties != null && certRequestProperties.isSetAuthnContextClassRefs()) {
      authnRequirements.setAuthnContextIdentifiers(certRequestProperties.getAuthnContextClassRefs()
          .stream()
          .map(s -> new SimpleAuthnContextIdentifier(s))
          .collect(Collectors.toList()));
    }

    final AttributeStatement signer = extension.getSigner();
    if (signer != null && signer.isSetAttributesAndEncryptedAttributes()) {
      final List<IdentityAttribute<?>> attributes = new ArrayList<>();
      for (final Object object : signer.getAttributesAndEncryptedAttributes()) {
        if (Attribute.class.isInstance(object)) {
          try {
            attributes.add(attributeConverter.convert(Attribute.class.cast(object)));
          }
          catch (final AttributeException e) {
            // Already checked in assertCorrectMessage
          }
        }
      }
      authnRequirements.setRequestedSignerAttributes(attributes);
    }

    return authnRequirements;
  }

  /** {@inheritDoc} */
  @Override
  public SignMessage getSignMessage() {
    return Optional.ofNullable(this.signRequest.getSignRequestExtension())
        .map(SignRequestExtension::getSignMessage)
        .map(m -> new DssSignMessage(m))
        .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public SignatureRequirements getSignatureRequirements() {
    return Optional.ofNullable(this.signRequest.getSignRequestExtension())
        .map(SignRequestExtension::getRequestedSignatureAlgorithm)
        .filter(StringUtils::isNotBlank)
        .map(a -> new DefaultSignatureRequirements(a))
        .orElseThrow(() -> new DssProtocolException("RequestedSignatureAlgorithm is missing - this field is required"));
  }

  /** {@inheritDoc} */
  @Override
  public SigningCertificateRequirements getSigningCertificateRequirements() {
    final CertRequestProperties props = Optional.ofNullable(this.signRequest.getSignRequestExtension())
        .map(SignRequestExtension::getCertRequestProperties)
        .orElse(null);
    if (props == null) {
      return null;
    }
    final DefaultSigningCertificateRequirements signingReqs = new DefaultSigningCertificateRequirements();
    if (props.getCertType() != null) {
      signingReqs.setCertificateType(CertificateType.fromType(props.getCertType()));
    }
    if (props.isSetRequestedCertAttributes()) {
      final List<CertificateAttributeMapping> mappings = new ArrayList<>();
      for (final MappedAttributeType a : props.getRequestedCertAttributes().getRequestedCertAttributes()) {

        final DefaultCertificateAttributeMapping cam = new DefaultCertificateAttributeMapping();

        final CertificateAttributeType attrType = Optional.ofNullable(a.getCertNameType())
            .map(CertificateAttributeType::fromType)
            .orElse(null);
        final DefaultRequestedCertificateAttribute rca = new DefaultRequestedCertificateAttribute(
            attrType, a.getCertAttributeRef(), a.getFriendlyName());
        rca.setDefaultValue(a.getDefaultValue());
        rca.setRequired(a.isSetRequired() ? a.isRequired() : null);
        cam.setDestination(rca);

        if (a.isSetSamlAttributeNames()) {
          final Map<Integer, IdentityAttributeIdentifier> sources = new HashMap<>();
          for (final PreferredSAMLAttributeNameType samlAttr : a.getSamlAttributeNames()) {
            final DefaultIdentityAttributeIdentifier sa =
                new DefaultIdentityAttributeIdentifier("SAML", samlAttr.getValue(), null);
            sources.put(Integer.valueOf(samlAttr.getOrder()), sa);
          }
          cam.setSources(sources.entrySet()
              .stream()
              .sorted(Map.Entry.comparingByKey())
              .map(Map.Entry::getValue)
              .collect(Collectors.toList()));
        }
        mappings.add(cam);
      }
      signingReqs.setAttributeMappings(mappings);
    }
    return signingReqs;
  }

  /** {@inheritDoc} */
  @Override
  public List<RequestedSignatureTask> getSignatureTasks() {
    final SignTasks signTasks = this.signRequest.getSignTasks();
    if (signTasks == null || !signTasks.isSetSignTaskDatas()) {
      return Collections.emptyList();
    }
    final List<RequestedSignatureTask> signatureTasks = new ArrayList<>();
    for (final SignTaskData std : signTasks.getSignTaskDatas()) {
      final DefaultRequestedSignatureTask task = new DefaultRequestedSignatureTask();
      task.setTaskId(std.getSignTaskId());
      if (std.isSetSigType()) {
        task.setSignatureType(std.getSigType());
      }
      task.setAdESType(std.getAdESType());
      if (std.isSetAdESObject()) {
        task.setAdESObject(
            new DefaultAdESObject(std.getAdESObject().getSignatureId(), std.getAdESObject().getAdESObjectBytes()));
      }
      task.setProcessingRulesUri(std.getProcessingRules());
      task.setTbsData(std.getToBeSignedBytes());

      if (std.getBase64Signature() != null) {
        final String msg = "Bad sign task in request - contains signature";
        log.info("{} [request-id: '{}']", msg, this.signRequest.getRequestID());
        throw new DssProtocolException(msg);
      }
      signatureTasks.add(task);
    }
    return signatureTasks;
  }

  /**
   * Gets the JAXB representation of the SignRequest
   *
   * @return JAXB SignRequest
   */
  public SignRequest getJaxbObject() {
    return this.signRequest.getWrappedSignRequest();
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    try {
      final Document doc = JAXBMarshaller.marshall(this.signRequest.getWrappedSignRequest());
      return DOMUtils.prettyPrint(doc);
    }
    catch (final Exception e) {
      log.info("Failed to marshall SignRequest message", e);
      return "-- Marshalling error --";
    }
  }

  /**
   * Since this class is Serializable, and we don't want to do our own serializing, we simply mark the XML document as
   * transient. Therefore, it may be {@code null} if this object was created from its serialized form.
   *
   * @return the SignRequest XML
   */
  private Document getXml() {
    if (this.xml == null) {
      try {
        this.xml = JAXBMarshaller.marshall(this.signRequest.getWrappedSignRequest());
      }
      catch (final JAXBException e) {
        throw new DssProtocolException("Failed to marshall SignRequest", e);
      }
    }
    return this.xml;
  }

}
