/*
 * Copyright 2022-2024 Sweden Connect
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

import java.io.Serializable;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.xpath.XPathExpressionException;

import org.apache.xml.security.Init;
import org.w3c.dom.Document;

import jakarta.xml.bind.JAXBException;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.sign.xml.XMLSignatureLocation;
import se.idsec.signservice.security.sign.xml.XMLSignatureLocation.ChildPosition;
import se.idsec.signservice.security.sign.xml.XMLSignerResult;
import se.idsec.signservice.security.sign.xml.impl.DefaultXMLSigner;
import se.idsec.signservice.utils.ProtocolVersion;
import se.idsec.signservice.xml.DOMUtils;
import se.swedenconnect.schemas.csig.dssext_1_1.AdESObject;
import se.swedenconnect.schemas.csig.dssext_1_1.Base64Signature;
import se.swedenconnect.schemas.csig.dssext_1_1.ContextInfo;
import se.swedenconnect.schemas.csig.dssext_1_1.SamlAssertions;
import se.swedenconnect.schemas.csig.dssext_1_1.SignResponseExtension;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTasks;
import se.swedenconnect.schemas.csig.dssext_1_1.SignatureCertificateChain;
import se.swedenconnect.schemas.csig.dssext_1_1.SignerAssertionInfo;
import se.swedenconnect.schemas.dss_1_0.InternationalStringType;
import se.swedenconnect.schemas.dss_1_0.Result;
import se.swedenconnect.schemas.saml_2_0.assertion.Attribute;
import se.swedenconnect.schemas.saml_2_0.assertion.AttributeStatement;
import se.swedenconnect.schemas.saml_2_0.assertion.NameIDType;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.utils.X509Utils;
import se.swedenconnect.signservice.authn.AuthnContextIdentifier;
import se.swedenconnect.signservice.authn.impl.DefaultIdentityAssertion;
import se.swedenconnect.signservice.authn.impl.SimpleAuthnContextIdentifier;
import se.swedenconnect.signservice.core.attribute.AttributeException;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.protocol.ProtocolException;
import se.swedenconnect.signservice.protocol.ProtocolProcessingRequirements;
import se.swedenconnect.signservice.protocol.SignResponseMessage;
import se.swedenconnect.signservice.protocol.SignResponseResult;
import se.swedenconnect.signservice.protocol.dss.jaxb.JaxbAttributeConverter;
import se.swedenconnect.signservice.protocol.msg.SignerAuthnInfo;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultSignerAuthnInfo;
import se.swedenconnect.signservice.signature.AdESType;
import se.swedenconnect.signservice.signature.CompletedSignatureTask;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.impl.DefaultAdESObject;
import se.swedenconnect.signservice.signature.impl.DefaultCompletedSignatureTask;
import se.swedenconnect.xml.jaxb.JAXBMarshaller;

/**
 * An implementation of the {@link SignResponseMessage} interface for sign request messages according to <a href=
 * "https://docs.swedenconnect.se/technical-framework/latest/09_-_DSS_Extension_for_Federated_Signing_Services.html">DSS
 * Extension for Federated Central Signing Services</a>.
 */
@Slf4j
class DssSignResponseMessage implements SignResponseMessage {

  /** For serializing. */
  private static final long serialVersionUID = -3890374307064822991L;

  /** 1.1 version. */
  private static ProtocolVersion VERSION_1_1 = ProtocolVersion.valueOf("1.1");

  /** Processing requirements. */
  private static final ProtocolProcessingRequirements processingRequirements = new DssProtocolProcessingRequirements();

  /** For creating JAXB/XML objects. */
  private static DatatypeFactory datatypeFactory;

  /** The attribute converter that converts between JAXB and the generic attribute representation. */
  private static JaxbAttributeConverter attributeConverter = new JaxbAttributeConverter();

  /** Where to insert the XML signature. */
  private static XMLSignatureLocation xmlSignatureLocation;

  /** Configuration object used when building a response. */
  private ResponseConfiguration configuration;

  /** The JAXB representation of the SignResponse. */
  private SignResponseWrapper signResponse;

  /**
   * The destination URL is not represented in a SignResponse, but we need the information when sending the response.
   */
  private String destinationUrl;

  /** The signed SignResponse. */
  private transient Document signedResponse;

  static {
    try {
      datatypeFactory = DatatypeFactory.newInstance();
    }
    catch (final DatatypeConfigurationException e) {
      throw new DssProtocolException("Failed to setup DatatypeFactory", e);
    }

    try {
      xmlSignatureLocation = new XMLSignatureLocation("/*/*[local-name()='OptionalOutputs']", ChildPosition.LAST);
    }
    catch (final XPathExpressionException e) {
      throw new RuntimeException(e);
    }

    // Apache XML security
    if (!Init.isInitialized()) {
      Init.init();
    }
  }

  /**
   * Constructor.
   *
   * @param configuration the protocol configuration
   * @param signRequest the corresponding SignRequest
   */
  public DssSignResponseMessage(final ResponseConfiguration configuration, final DssSignRequestMessage signRequest) {
    this.configuration = Optional.ofNullable(configuration).orElseGet(() -> new ResponseConfiguration());
    Objects.requireNonNull(signRequest, "signRequest must not be null");

    final ProtocolVersion version = signRequest.getVersion();

    this.signResponse = new SignResponseWrapper();
    this.signResponse.setProfile(DssConstants.DSS_PROFILE);
    this.signResponse.setSignResponseExtension(new SignResponseExtension());
    this.signResponse.getSignResponseExtension().setVersion(version.toString());

    this.setInResponseTo(
        Objects.requireNonNull(signRequest.getRequestId(), "RequestID not set in SignRequest"));
    this.setIssuerId(
        Objects.requireNonNull(signRequest.getSignServiceId(), "SignServiceId not set in SignRequest"));
    this.setDestinationUrl(
        Objects.requireNonNull(signRequest.getResponseUrl(), "ResponseUrl not set in SignRequest"));

    // Should we include the encoded SignRequest in the response message?
    //
    if (this.configuration.includeRequestMessage || version.compareTo(VERSION_1_1) <= 0) {
      this.setSignRequestMessage(signRequest);
    }
  }

  /** {@inheritDoc} */
  @Override
  public ProtocolProcessingRequirements getProcessingRequirements() {
    return processingRequirements;
  }

  /** {@inheritDoc} */
  @Override
  public void sign(final PkiCredential signatureCredential) throws SignatureException {

    if (this.getSignResponseResult() == null) {
      throw new DssProtocolException("No SignResponseResult has been assigned");
    }

    // If it still haven't been assigned, set the "issued at" to the current time.
    if (this.getIssuedAt() == null) {
      this.setIssuedAt(Instant.now());
    }
    try {
      // First marshall the JAXB to a DOM document ...
      //
      final Document signResponseDocument = JAXBMarshaller.marshall(this.signResponse.getWrappedSignResponse());

      log.trace("Signing: {}", DOMUtils.prettyPrint(signResponseDocument));

      // Get a signer and sign the message ...
      //
      final DefaultXMLSigner signer = new DefaultXMLSigner(signatureCredential);
      signer.setSignatureLocation(xmlSignatureLocation);
      signer.setXPathTransform(null);
      final XMLSignerResult signerResult = signer.sign(signResponseDocument);
      log.debug("SignResponse '{}' successfully signed", this.signResponse.getRequestID());

      this.signedResponse = signerResult.getSignedDocument();
    }
    catch (final JAXBException e) {
      log.error("Error during signing of SignResponse - {}", e.getMessage(), e);
      throw new SignatureException("Failed to marshall SignResponse", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public String encode() throws ProtocolException {
    if (this.signedResponse == null) {
      throw new ProtocolException("SignResponse has not been signed - Can not encode");
    }
    return DOMUtils.nodeToBase64(this.signedResponse);
  }

  /**
   * Does nothing. The RelayState is always equal to InResponseTo.
   */
  @Override
  public void setRelayState(final String relayState) {
  }

  /** {@inheritDoc} */
  @Override
  public String getRelayState() {
    return this.getInResponseTo();
  }

  /**
   * Gets the version of the SignResponse message.
   *
   * @return the version
   */
  public ProtocolVersion getVersion() {
    return Optional.ofNullable(this.signResponse.getSignResponseExtension())
        .map(SignResponseExtension::getVersion)
        .map(ProtocolVersion::valueOf)
        .orElse(ProtocolVersion.valueOf("1.1"));
  }

  /** {@inheritDoc} */
  @Override
  public String getInResponseTo() {
    return this.signResponse.getRequestID();
  }

  /** {@inheritDoc} */
  @Override
  public void setInResponseTo(final String requestId) {
    this.signResponse.setRequestID(requestId);
  }

  /** {@inheritDoc} */
  @Override
  public Instant getIssuedAt() {
    return Optional.of(this.signResponse.getSignResponseExtension())
        .map(SignResponseExtension::getResponseTime)
        .map(XMLGregorianCalendar::toGregorianCalendar)
        .map(GregorianCalendar::toInstant)
        .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  public void setIssuedAt(final Instant issuedAt) {
    this.signResponse.getSignResponseExtension().setResponseTime(
        Optional.ofNullable(issuedAt)
            .map(ia -> {
              final GregorianCalendar c = new GregorianCalendar();
              c.setTimeInMillis(ia.toEpochMilli());
              return datatypeFactory.newXMLGregorianCalendar(c);
            })
            .orElse(null));
  }

  /** {@inheritDoc} */
  @Override
  public String getIssuerId() {
    return Optional.of(this.signResponse.getSignResponseExtension())
        .map(SignResponseExtension::getSignerAssertionInfo)
        .map(SignerAssertionInfo::getContextInfo)
        .map(ContextInfo::getServiceID)
        .orElse(null);
  }

  /**
   * This implementation places the issuer ID in the otherwise worthless element ContextInfo:ServiceID.
   */
  @Override
  public void setIssuerId(final String issuerId) {
    if (this.signResponse.getSignResponseExtension().getSignerAssertionInfo() == null) {
      this.signResponse.getSignResponseExtension().setSignerAssertionInfo(new SignerAssertionInfo());
    }
    if (this.signResponse.getSignResponseExtension().getSignerAssertionInfo().getContextInfo() == null) {
      this.signResponse.getSignResponseExtension().getSignerAssertionInfo().setContextInfo(new ContextInfo());
    }
    this.signResponse.getSignResponseExtension().getSignerAssertionInfo().getContextInfo().setServiceID(issuerId);
  }

  /** {@inheritDoc} */
  @Override
  public String getDestinationUrl() {
    return this.destinationUrl;
  }

  /** {@inheritDoc} */
  @Override
  public void setDestinationUrl(final String destinationUrl) {
    this.destinationUrl = destinationUrl;
  }

  /** {@inheritDoc} */
  @Override
  public SignResponseResult getSignResponseResult() {
    return Optional.ofNullable(this.signResponse.getResult())
        .map(r -> new DssSignResponseResult(r))
        .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  public void setSignResponseResult(final SignResponseResult signResponseResult) {
    if (signResponseResult == null) {
      this.signResponse.setResult(null);
      return;
    }
    final Result result = new Result();
    result.setResultMajor(signResponseResult.getErrorCode());
    result.setResultMinor(signResponseResult.getMinorErrorCode());
    if (signResponseResult.getMessage() != null) {
      final InternationalStringType msg = new InternationalStringType();
      msg.setLang("en");
      msg.setValue(signResponseResult.getMessage());
      result.setResultMessage(msg);
    }
    this.signResponse.setResult(result);

    // If this is an error response, clear stuff that shouldn't be there.
    if (!signResponseResult.isSuccess()) {
      this.signResponse.getSignResponseExtension().setSignatureCertificateChain(null);
      this.signResponse.getSignResponseExtension().setSignerAssertionInfo(null);
      this.signResponse.setSignatureObject(null);
    }
  }

  /** {@inheritDoc} */
  @Override
  public SignerAuthnInfo getSignerAuthnInfo() {
    final SignerAssertionInfo sai =
        Optional.ofNullable(this.signResponse.getSignResponseExtension().getSignerAssertionInfo())
            .orElse(null);
    final ContextInfo ci = Optional.ofNullable(sai)
        .map(SignerAssertionInfo::getContextInfo)
        .orElse(null);

    if (sai == null || ci == null) {
      return null;
    }
    final DefaultIdentityAssertion identityAssertion = new DefaultIdentityAssertion();
    identityAssertion.setIdentifier(ci.getAssertionRef());
    identityAssertion.setIssuer(Optional.ofNullable(ci.getIdentityProvider())
        .map(NameIDType::getValue)
        .orElse(null));
    identityAssertion.setAuthnContext(Optional.ofNullable(ci.getAuthnContextClassRef())
        .map(a -> new SimpleAuthnContextIdentifier(a))
        .orElse(null));
    identityAssertion.setAuthnInstant(Optional.ofNullable(ci.getAuthenticationInstant())
        .map(XMLGregorianCalendar::toGregorianCalendar)
        .map(GregorianCalendar::toInstant)
        .orElse(null));

    identityAssertion.setEncodedAssertion(Optional.ofNullable(sai.getSamlAssertions())
        .filter(SamlAssertions::isSetAssertions)
        .map(SamlAssertions::getAssertions)
        .map(l -> l.get(0))
        .orElse(null));

    if (sai.isSetAttributeStatement() && sai.getAttributeStatement().isSetAttributesAndEncryptedAttributes()) {
      final List<IdentityAttribute<?>> attributes = new ArrayList<>();
      for (final Object object : sai.getAttributeStatement().getAttributesAndEncryptedAttributes()) {
        if (Attribute.class.isInstance(object)) {
          try {
            attributes.add(attributeConverter.convert(Attribute.class.cast(object)));
          }
          catch (final AttributeException e) {
            throw new DssProtocolException("Attribute conversion error", e);
          }
        }
      }
      identityAssertion.setIdentityAttributes(attributes);
    }
    identityAssertion.setScheme(Optional.ofNullable(ci.getAuthType()).orElseGet(() -> "SAML"));

    return new DefaultSignerAuthnInfo(identityAssertion);
  }

  /** {@inheritDoc} */
  @Override
  public void setSignerAuthnInfo(final SignerAuthnInfo signerAuthnInfo) {
    if (this.signResponse.getSignResponseExtension().getSignerAssertionInfo() == null) {
      this.signResponse.getSignResponseExtension().setSignerAssertionInfo(new SignerAssertionInfo());
    }
    if (this.signResponse.getSignResponseExtension().getSignerAssertionInfo().getContextInfo() == null) {
      this.signResponse.getSignResponseExtension().getSignerAssertionInfo().setContextInfo(new ContextInfo());
    }
    final ContextInfo contextInfo =
        this.signResponse.getSignResponseExtension().getSignerAssertionInfo().getContextInfo();

    // IdentityProvider
    contextInfo.setIdentityProvider(Optional.ofNullable(signerAuthnInfo.getIdentityAssertion().getIssuer())
        .map(i -> {
          final NameIDType idp = new NameIDType();
          idp.setValue(signerAuthnInfo.getIdentityAssertion().getIssuer());
          idp.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
          return idp;
        })
        .orElse(null));

    // AuthenticationInstant
    contextInfo.setAuthenticationInstant(Optional.ofNullable(signerAuthnInfo.getIdentityAssertion().getAuthnInstant())
        .map(ai -> {
          final GregorianCalendar c = new GregorianCalendar();
          c.setTimeInMillis(ai.toEpochMilli());
          return datatypeFactory.newXMLGregorianCalendar(c);
        })
        .orElse(null));

    // AuthnContextClassRef
    contextInfo.setAuthnContextClassRef(Optional.ofNullable(signerAuthnInfo.getIdentityAssertion().getAuthnContext())
        .map(AuthnContextIdentifier::getIdentifier)
        .orElse(null));

    // AuthType
    contextInfo.setAuthType(signerAuthnInfo.getIdentityAssertion().getScheme());

    // AssertionRef
    contextInfo.setAssertionRef(signerAuthnInfo.getIdentityAssertion().getIdentifier());

    // Assertion ...
    if (this.configuration.includeAssertion) {
      final byte[] encodedAssertion = signerAuthnInfo.getIdentityAssertion().getEncodedAssertion();
      if (encodedAssertion != null) {
        final SamlAssertions sa = new SamlAssertions();
        sa.getAssertions().add(encodedAssertion);
        this.signResponse.getSignResponseExtension().getSignerAssertionInfo().setSamlAssertions(sa);
      }
    }

    // Attributes
    if (signerAuthnInfo.getIdentityAssertion().getIdentityAttributes() != null) {
      final AttributeStatement attributeStatement = new AttributeStatement();
      for (final IdentityAttribute<?> attribute : signerAuthnInfo.getIdentityAssertion().getIdentityAttributes()) {
        try {
          final Attribute samlAttribute = attributeConverter.convert(attribute);
          attributeStatement.getAttributesAndEncryptedAttributes().add(samlAttribute);
        }
        catch (final AttributeException e) {
          final String msg = String.format("Invalid attribute (%s) - %s", attribute.getIdentifier(), e.getMessage());
          log.info("{}", msg);
          throw new DssProtocolException(msg, e);
        }
      }
      this.signResponse.getSignResponseExtension().getSignerAssertionInfo().setAttributeStatement(attributeStatement);
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> getSignatureCertificateChain() {
    if (!this.signResponse.getSignResponseExtension().isSetSignatureCertificateChain()) {
      return null;
    }
    return this.signResponse.getSignResponseExtension().getSignatureCertificateChain().getX509Certificates().stream()
        .map(b -> {
          try {
            return X509Utils.decodeCertificate(b);
          }
          catch (final CertificateException e) {
            throw new DssProtocolException("Failed to decode certificate", e);
          }
        })
        .collect(Collectors.toList());
  }

  /** {@inheritDoc} */
  @Override
  public void setSignatureCertificateChain(final List<X509Certificate> chain) {
    if (chain != null) {
      final SignatureCertificateChain certs = new SignatureCertificateChain();
      for (final X509Certificate c : chain) {
        try {
          certs.getX509Certificates().add(c.getEncoded());
        }
        catch (final CertificateEncodingException e) {
          throw new DssProtocolException("Failed to encode supplied certificate", e);
        }
      }
      this.signResponse.getSignResponseExtension().setSignatureCertificateChain(certs);
    }
    else {
      this.signResponse.getSignResponseExtension().setSignatureCertificateChain(null);
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<CompletedSignatureTask> getSignatureTasks() {
    final SignTasks signTasks = this.signResponse.getSignTasks();
    if (signTasks == null || !signTasks.isSetSignTaskDatas()) {
      return null;
    }
    final List<CompletedSignatureTask> tasks = new ArrayList<>();
    for (final SignTaskData std : signTasks.getSignTaskDatas()) {
      final DefaultCompletedSignatureTask cst = new DefaultCompletedSignatureTask();
      cst.setTaskId(std.getSignTaskId());
      cst.setSignatureType(std.getSigType());
      cst.setAdESType(std.getAdESType());
      cst.setAdESObject(Optional.ofNullable(std.getAdESObject())
          .map(a -> new DefaultAdESObject(a.getSignatureId(), a.getAdESObjectBytes()))
          .orElse(null));
      cst.setProcessingRulesUri(std.getProcessingRules());
      cst.setTbsData(std.getToBeSignedBytes());
      cst.setSignatureAlgorithmUri(Optional.ofNullable(std.getBase64Signature())
          .map(Base64Signature::getType)
          .orElse(null));
      cst.setSignature(Optional.ofNullable(std.getBase64Signature())
          .map(Base64Signature::getValue)
          .orElse(null));

      tasks.add(cst);
    }
    return tasks;
  }

  /** {@inheritDoc} */
  @Override
  public void setSignatureTasks(final List<CompletedSignatureTask> signatureTasks) {
    if (signatureTasks != null && !signatureTasks.isEmpty()) {
      final SignTasks signTasks = new SignTasks();
      for (final CompletedSignatureTask t : signatureTasks) {
        final SignTaskData std = new SignTaskData();
        std.setToBeSignedBytes(t.getTbsData());
        std.setAdESObject(Optional.ofNullable(t.getAdESObject())
            .map(a -> {
              final AdESObject ao = new AdESObject();
              ao.setSignatureId(a.getSignatureId());
              ao.setAdESObjectBytes(a.getObjectBytes());
              return ao;
            })
            .orElse(null));
        std.setBase64Signature(Optional.ofNullable(t.getSignature())
            .map(s -> {
              final Base64Signature bs = new Base64Signature();
              bs.setValue(s);
              bs.setType(t.getSignatureAlgorithmUri());
              return bs;
            })
            .orElse(null));
        std.setSignTaskId(t.getTaskId());
        std.setSigType(Optional.ofNullable(t.getSignatureType()).map(SignatureType::getType).orElse(null));
        std.setAdESType(Optional.ofNullable(t.getAdESType()).map(AdESType::name).orElse("None"));
        std.setProcessingRules(t.getProcessingRulesUri());

        signTasks.getSignTaskDatas().add(std);
      }
      this.signResponse.setSignTasks(signTasks);
    }
    else {
      this.signResponse.setSignTasks(null);
    }
  }

  /**
   * Assigns the encoded SignRequest message.
   *
   * @param signRequest the SignRequest
   */
  public void setSignRequestMessage(final DssSignRequestMessage signRequest) {
    if (signRequest != null) {
      try {
        this.signResponse.getSignResponseExtension().setRequest(
            DOMUtils.nodeToBytes(JAXBMarshaller.marshall(signRequest.getJaxbObject())));
      }
      catch (final Exception e) {
        throw new DssProtocolException("Failed to marshall SignRequest", e);
      }
    }
    else {
      this.signResponse.getSignResponseExtension().setRequest(null);
    }
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    try {
      final Document doc = JAXBMarshaller.marshall(this.signResponse.getWrappedSignResponse());
      return DOMUtils.prettyPrint(doc);
    }
    catch (final Exception e) {
      log.info("Failed to marshall SignResponse message", e);
      return "-- Marshalling error --";
    }
  }

  /**
   * Configuration for response messages.
   */
  static class ResponseConfiguration implements Serializable {

    private static final long serialVersionUID = 288455638407072741L;

    /** Setting that tells whether SAML assertions should be included in the response messages. */
    public boolean includeAssertion = true;

    /**
     * Setting that tells whether to include the request message in the response messages created. For 1.1 version and
     * below this will always be included, but in greater versions the field is optional.
     */
    public boolean includeRequestMessage = false;
  }

}
