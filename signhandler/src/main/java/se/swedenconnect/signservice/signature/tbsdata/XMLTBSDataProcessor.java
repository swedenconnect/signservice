/*
 * Copyright 2022-2025 Sweden Connect
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
package se.swedenconnect.signservice.signature.tbsdata;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Random;
import java.util.stream.Collectors;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.binding.xmldsig.CanonicalizationMethodType;
import org.apache.xml.security.binding.xmldsig.DigestMethodType;
import org.apache.xml.security.binding.xmldsig.ObjectType;
import org.apache.xml.security.binding.xmldsig.ReferenceType;
import org.apache.xml.security.binding.xmldsig.SignatureMethodType;
import org.apache.xml.security.binding.xmldsig.SignedInfoType;
import org.apache.xml.security.binding.xmldsig.TransformType;
import org.apache.xml.security.binding.xmldsig.TransformsType;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.parser.XMLParserException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.xml.bind.JAXBException;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.xml.DOMUtils;
import se.swedenconnect.schemas.etsi.xades_1_3_2.CertIDTypeV2;
import se.swedenconnect.schemas.etsi.xades_1_3_2.DigestAlgAndValueType;
import se.swedenconnect.schemas.etsi.xades_1_3_2.QualifyingProperties;
import se.swedenconnect.schemas.etsi.xades_1_3_2.SignedProperties;
import se.swedenconnect.schemas.etsi.xades_1_3_2.SignedSignatureProperties;
import se.swedenconnect.schemas.etsi.xades_1_3_2.SigningCertificateV2;
import se.swedenconnect.security.algorithms.MessageDigestAlgorithm;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.signature.AdESObject;
import se.swedenconnect.signservice.signature.AdESType;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.impl.DefaultAdESObject;
import se.swedenconnect.xml.jaxb.JAXBMarshaller;
import se.swedenconnect.xml.jaxb.JAXBUnmarshaller;

/**
 * XML Data to be signed processor.
 */
@Slf4j
public class XMLTBSDataProcessor extends AbstractTBSDataProcessor {

  /** URI identifier for XAdES SignedProperties */
  public static String SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties";

  /** XAdES XML name space URI */
  public static String XADES_XML_NS = "http://uri.etsi.org/01903/v1.3.2#";

  /** SignedProperties element name */
  public static String SIGNED_PROPERTIES_ELEMENT_NAME = "SignedProperties";

  /**
   * Default canonicalization algorithm.
   *
   * @param defaultCanonicalizationAlgorithm set default canonicalization algorithm
   */
  @Setter
  private String defaultCanonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";

  /** Object factory for XML digital signature elements */
  public static final org.apache.xml.security.binding.xmldsig.ObjectFactory dsObjectFactory =
      new org.apache.xml.security.binding.xmldsig.ObjectFactory();

  /** Object factory for XAdES digital signature elements */
  public static final se.swedenconnect.schemas.etsi.xades_1_3_2.ObjectFactory xadesObjectFactory =
      new se.swedenconnect.schemas.etsi.xades_1_3_2.ObjectFactory();

  /** Transformer for transforming XML fragments to bytes without XML declaration */
  public static Transformer xmlFragmentTransformer;

  private static final Random RNG = new SecureRandom();

  static {
    final TransformerFactory transformerFactory = TransformerFactory.newInstance();
    try {
      xmlFragmentTransformer = transformerFactory.newTransformer();
      xmlFragmentTransformer.setOutputProperty("omit-xml-declaration", "yes");
    }
    catch (final TransformerConfigurationException e) {
      throw new SecurityException(e);
    }
  }

  /**
   * Constructor for this XML TBS data processor with default settings.
   */
  public XMLTBSDataProcessor() {
    super(null);
  }

  /**
   * Constructor that allows setting of supported processing rules.
   *
   * @param supportedProcessingRules list of supported processing rules for this TBS data processor
   */
  public XMLTBSDataProcessor(@Nonnull final List<String> supportedProcessingRules) {
    super(supportedProcessingRules);
  }

  /** {@inheritDoc} */
  @Override
  public boolean supportsType(@Nonnull final SignatureType signatureType) {
    return signatureType == SignatureType.XML;
  }

  /** {@inheritDoc} */
  @Override
  protected void checkToBeSignedData(@Nonnull final byte[] tbsData, final boolean ades,
      @Nullable final AdESObject adESObject, @Nonnull final SignatureAlgorithm signatureAlgorithm)
      throws InvalidRequestException {
    log.debug("Checking XML to be signed data");

    try {
      if (ades) {
        if (adESObject == null) {
          throw new InvalidRequestException(
              "the AdESObject must not be null when the signature is an AdES XML signature");
        }
        Optional.ofNullable(adESObject.getSignatureId())
            .orElseThrow(() -> new InvalidRequestException("Signature ID must not be null in a XAdES signature"));
      }

      // Checking any present signing time if it is too old or not yet valid
      if (adESObject != null && adESObject.getObjectBytes() != null) {
        final Document adesObjectDocument = DOMUtils.bytesToDocument(adESObject.getObjectBytes());
        final ObjectType adesObjectType = JAXBUnmarshaller.unmarshall(adesObjectDocument, ObjectType.class);
        final XadesQualifyingProperties xadesObject = new XadesQualifyingProperties(adesObjectType);
        // We only care about signing time if is set
        if (xadesObject.getSigningTime() != null) {
          // A signing time is present, check that it is current.
          this.checkSigningTime(Instant.ofEpochMilli(xadesObject.getSigningTime()));
        }
      }

      final Document tbsDocument = DOMUtils.bytesToDocument(tbsData);
      final SignedInfoType signedInfo = JAXBUnmarshaller.unmarshall(tbsDocument, SignedInfoType.class);

      // Check algorithm consistency (the data to be signed must match the requested algorithm)
      final SignatureMethodType signatureMethod = Optional.ofNullable(signedInfo.getSignatureMethod())
          .orElseThrow(() -> new NoSuchAlgorithmException("SignInfo does not have a specified signature algorithm"));
      if (!signatureAlgorithm.getUri().equals(signatureMethod.getAlgorithm())) {
        throw new IOException("Signature algorithm of request does not match provided data to be signed");
      }

      final List<ReferenceType> referenceList = signedInfo.getReference();
      if (referenceList == null || referenceList.isEmpty()) {
        // We do require at least one reference to signed data
        throw new InvalidRequestException("Input SignedInfo does not contain any reference data");
      }
      final List<ReferenceType> xadesReferenceList = referenceList.stream()
          .filter(referenceType -> SIGNED_PROPERTIES_TYPE.equalsIgnoreCase(referenceType.getType()))
          .collect(Collectors.toList());

      if (xadesReferenceList.size() > 1) {
        // We do not allow more than one XAdES SignedProperties reference
        throw new InvalidRequestException("SignedInfo has more than one XAdES reference");
      }

    }
    catch (final JAXBException | NoSuchAlgorithmException | IOException | DOMException | SignatureException e) {
      throw new InvalidRequestException(e.getMessage(), e);
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public TBSProcessingData processSignatureTypeTBSData(@Nonnull final RequestedSignatureTask signatureTask,
      @Nonnull final X509Certificate signerCertificate, @Nonnull final SignatureAlgorithm signatureAlgorithm)
      throws SignatureException {
    log.debug("Processing XML to be signed data");

    // Check and collect data
    this.defaultProcessingRuleCheck(signatureTask.getProcessingRulesUri());
    final byte[] tbsBytes = signatureTask.getTbsData();
    final SignatureType signatureType = signatureTask.getSignatureType();
    if (!signatureType.equals(SignatureType.XML)) {
      throw new SignatureException("Signature type must be XML");
    }
    final AdESType adESType = signatureTask.getAdESType();
    final AdESObject adESObject = signatureTask.getAdESObject();
    final boolean xades = AdESType.BES.equals(adESType) || AdESType.EPES.equals(adESType);
    log.debug("XAdES signature = {}", xades);

    // Process TBS data
    try {
      if (xades) {
        final String signatureId = Optional.ofNullable(adESObject.getSignatureId())
            .orElseThrow(() -> new SignatureException("Signature ID must not be null in a XAdES signature"));
        final byte[] adesObjectBytes = adESObject.getObjectBytes();
        XadesQualifyingProperties xadesObject;
        if (adesObjectBytes == null) {
          xadesObject = XadesQualifyingProperties.createXadesQualifyingProperties();
        }
        else {
          final Document adesObjectDocument = DOMUtils.bytesToDocument(adesObjectBytes);
          final ObjectType adesObjectType = JAXBUnmarshaller.unmarshall(adesObjectDocument, ObjectType.class);
          xadesObject = new XadesQualifyingProperties(adesObjectType);
        }

        final Element adesElement = xadesObject.getAdesElement();
        final QualifyingProperties qualifyingProperties = Optional.ofNullable(this.getQualifyingProperties(adesElement))
            .orElseThrow(
                () -> new SignatureException("Failed to obtain QualifyingProperties from provided AdES object"));
        final String ref = this.addSigningCertRef(signerCertificate, qualifyingProperties, signatureId,
            signatureAlgorithm);
        final Element updatedAdesElement = this.getUpdatedAdesElement(qualifyingProperties);
        final byte[] updatedAdesObjectBytes = nodeToBytes(updatedAdesElement);
        final byte[] updatedTbsData = this.getUpdatedTbsData(tbsBytes, updatedAdesElement, signatureAlgorithm, ref);

        final AdESObject updatedAdesObject = new DefaultAdESObject(signatureId, updatedAdesObjectBytes);

        return TBSProcessingData.builder()
            .processingRules(signatureTask.getProcessingRulesUri())
            .adesObject(updatedAdesObject)
            .tbsBytes(updatedTbsData)
            .build();
      }
      else {
        return TBSProcessingData.builder()
            .processingRules(signatureTask.getProcessingRulesUri())
            .tbsBytes(tbsBytes)
            .build();
      }
    }
    catch (SignatureException | JAXBException | DatatypeConfigurationException | NoSuchAlgorithmException
        | CertificateEncodingException | IOException | XMLParserException | InvalidCanonicalizerException
        | CanonicalizationException | ParserConfigurationException | SAXException e) {
      throw new SignatureException("Unable to parse data to be signed in request:" + e, e);
    }
  }

  /**
   * Adds signer certificate reference to AdES object.
   *
   * @param certificate certificate to reference in AdES object
   * @param qualifyingProperties QualifyingProperties to update
   * @param signatureId the id of the Signature being updated
   * @param signatureAlgorithm the XML signature algorithm
   * @return the id of the SignedProperties element being signed inside QualifyingProperties
   * @throws DatatypeConfigurationException on error extending QualifyingProperties
   * @throws NoSuchAlgorithmException on error extending QualifyingProperties
   * @throws CertificateEncodingException on error extending QualifyingProperties
   * @throws IOException on error extending QualifyingProperties
   */
  @Nonnull
  private String addSigningCertRef(@Nonnull final X509Certificate certificate,
      @Nonnull final QualifyingProperties qualifyingProperties,
      @Nonnull final String signatureId, final @Nonnull SignatureAlgorithm signatureAlgorithm)
      throws DatatypeConfigurationException, NoSuchAlgorithmException, CertificateEncodingException, IOException {

    // Set the expected signature ID ref
    qualifyingProperties.setTarget("#" + signatureId);

    // Add or create SignedProperties
    if (!qualifyingProperties.isSetSignedProperties()) {
      qualifyingProperties.setSignedProperties(xadesObjectFactory.createSignedProperties());
    }
    final SignedProperties signedProperties = qualifyingProperties.getSignedProperties();
    String signedPropertiesId = signedProperties.getId();
    if (signedPropertiesId == null) {
      signedPropertiesId = "xades-id-" + new BigInteger(128, RNG).toString(16);
      signedProperties.setId(signedPropertiesId);
    }
    // Add or create SignedSignatureProperties
    if (!signedProperties.isSetSignedSignatureProperties()) {
      signedProperties.setSignedSignatureProperties(xadesObjectFactory.createSignedSignatureProperties());
    }
    final SignedSignatureProperties signedSignatureProperties = signedProperties.getSignedSignatureProperties();
    // Set signing time to current time
    final XMLGregorianCalendar signingTime =
        DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar());
    signedSignatureProperties.setSigningTime(signingTime);
    if (signedSignatureProperties.isSetSigningCertificate()) {
      // There is an old outdated certificate reference deltet it
      signedSignatureProperties.setSigningCertificate(null);
      log.debug("AdES object from sign request contained V1 certificate reference. This was deleted");
    }

    // Hash certificate
    final MessageDigestAlgorithm messageDigestAlgorithm = signatureAlgorithm.getMessageDigestAlgorithm();
    final MessageDigest md = MessageDigest.getInstance(messageDigestAlgorithm.getJcaName());
    final byte[] certDigest = md.digest(certificate.getEncoded());

    // Create and set a new instance of signingCertificateV2
    signedSignatureProperties.setSigningCertificateV2(xadesObjectFactory.createSigningCertificateV2());
    final SigningCertificateV2 signingCertificateV2 = signedSignatureProperties.getSigningCertificateV2();
    final List<CertIDTypeV2> certs = signingCertificateV2.getCerts();
    final CertIDTypeV2 certIDTypeV2 = xadesObjectFactory.createCertIDTypeV2();
    final DigestAlgAndValueType digestAlgAndValueType = xadesObjectFactory.createDigestAlgAndValueType();
    final DigestMethodType digestMethodType = dsObjectFactory.createDigestMethodType();
    digestMethodType.setAlgorithm(messageDigestAlgorithm.getUri());
    digestAlgAndValueType.setDigestMethod(digestMethodType);
    digestAlgAndValueType.setDigestValue(certDigest);
    certIDTypeV2.setCertDigest(digestAlgAndValueType);
    if (this.isIncludeIssuerSerial()) {
      final byte[] issuerSerial = getRfc5035IssuerSerialBytes(certificate);
      certIDTypeV2.setIssuerSerialV2(issuerSerial);
    }
    certs.add(certIDTypeV2);

    return signedPropertiesId;
  }

  /**
   * Updates the SignedInfo based on an updated XAdES object.
   *
   * @param tbsBytes input unmodified SignedInfo
   * @param updatedAdesElement the updated XAdES object with updated certificate reference
   * @param signatureAlgorithm signature algorithm used to sign XML
   * @param ref the reference ID used to identify XAdES signed properties
   * @return updated canonical SignedInfo bytes
   * @throws JAXBException on error processing and updating SignedInfo
   * @throws SignatureException on error processing and updating SignedInfo
   * @throws XMLParserException on error processing and updating SignedInfo
   * @throws InvalidCanonicalizerException on error processing and updating SignedInfo
   * @throws CanonicalizationException on error processing and updating SignedInfo
   * @throws ParserConfigurationException on error processing and updating SignedInfo
   * @throws IOException on error processing and updating SignedInfo
   * @throws SAXException on error processing and updating SignedInfo
   * @throws NoSuchAlgorithmException on error processing and updating SignedInfo
   */
  @Nonnull
  private byte[] getUpdatedTbsData(@Nonnull final byte[] tbsBytes, @Nonnull final Element updatedAdesElement,
      @Nonnull final SignatureAlgorithm signatureAlgorithm, @Nonnull final String ref)
      throws JAXBException, SignatureException, XMLParserException, InvalidCanonicalizerException,
      CanonicalizationException, ParserConfigurationException, IOException, SAXException, NoSuchAlgorithmException {

    final Document tbsDocument = DOMUtils.bytesToDocument(tbsBytes);
    final SignedInfoType signedInfo = JAXBUnmarshaller.unmarshall(tbsDocument, SignedInfoType.class);

    final List<ReferenceType> referenceList = signedInfo.getReference();
    final List<ReferenceType> xadesReferenceList = referenceList.stream()
        .filter(referenceType -> SIGNED_PROPERTIES_TYPE.equalsIgnoreCase(referenceType.getType()))
        .collect(Collectors.toList());

    if (xadesReferenceList.isEmpty()) {
      final ReferenceType newXadesRef = dsObjectFactory.createReferenceType();
      newXadesRef.setType(SIGNED_PROPERTIES_TYPE);
      referenceList.add(newXadesRef);
    }

    final ReferenceType xadesReference = referenceList.stream()
        .filter(referenceType -> SIGNED_PROPERTIES_TYPE.equalsIgnoreCase(referenceType.getType()))
        .findFirst().orElseThrow();

    xadesReference.setURI("#" + ref);
    // Set digest method
    final DigestMethodType digestMethodType = dsObjectFactory.createDigestMethodType();
    digestMethodType.setAlgorithm(signatureAlgorithm.getMessageDigestAlgorithm().getUri());
    xadesReference.setDigestMethod(digestMethodType);

    // Set digest value
    final Node signedPropertiesNode = updatedAdesElement.getElementsByTagNameNS(XADES_XML_NS,
        SIGNED_PROPERTIES_ELEMENT_NAME).item(0);
    final byte[] signedPropertyBytes = getCanonicalXml(nodeToBytes(signedPropertiesNode),
        this.defaultCanonicalizationAlgorithm);
    final MessageDigest md = MessageDigest.getInstance(signatureAlgorithm.getMessageDigestAlgorithm().getJcaName());
    final byte[] signedPropertyHash = md.digest(signedPropertyBytes);
    xadesReference.setDigestValue(signedPropertyHash);

    // Set transform algo
    final TransformType transform = dsObjectFactory.createTransformType();
    transform.setAlgorithm(this.defaultCanonicalizationAlgorithm);
    final TransformsType transforms = dsObjectFactory.createTransformsType();
    transforms.getTransform().add(transform);
    xadesReference.setTransforms(transforms);

    // Done updating SignedInfo. Finally, transform SignedInfo to bytes
    final CanonicalizationMethodType canonicalizationMethodType = Optional.ofNullable(
        signedInfo.getCanonicalizationMethod())
        .orElseThrow(() -> new SignatureException(
            "SignedInfo has no canonicalization algorithm element"));
    final String canonicalizationAlgorithm = Optional.ofNullable(canonicalizationMethodType.getAlgorithm())
        .orElseThrow(() -> new SignatureException(
            "SignedInfo has no canonicalization algorithm"));
    return getCanonicalXml(nodeToBytes(
        JAXBMarshaller.marshallNonRootElement(dsObjectFactory.createSignedInfo(signedInfo)).getDocumentElement()),
        canonicalizationAlgorithm);
  }

  /**
   * Get canonical XML from XML input.
   *
   * @param xmlBytes XML data to canonicalize
   * @param canonicalizationAlgo canonicalization algorithm
   * @return canonical XML
   * @throws InvalidCanonicalizerException bad canonicalization algorithm
   * @throws IOException data parsing error
   * @throws CanonicalizationException canonicalization error
   * @throws XMLParserException error parsing XML input
   */
  @Nonnull
  public static byte[] getCanonicalXml(@Nonnull final byte[] xmlBytes, @Nonnull final String canonicalizationAlgo)
      throws InvalidCanonicalizerException, IOException, CanonicalizationException, XMLParserException {
    Objects.requireNonNull(xmlBytes, "XML Bytes to canonicalize must not be null");
    Objects.requireNonNull(canonicalizationAlgo, "Canonicalization algorithm must be specified");
    final Canonicalizer canon = Canonicalizer.getInstance(canonicalizationAlgo);
    try (final ByteArrayOutputStream os = new ByteArrayOutputStream()) {
      canon.canonicalize(xmlBytes, os, true);
      return os.toByteArray();
    }
  }

  /**
   * Transforms an XML node to bytes without XML declaration.
   *
   * @param node node to transform to byte
   * @return byte representation of the XML node without XML declaration
   */
  @Nonnull
  public static byte[] nodeToBytes(@Nonnull final Node node) {
    try (final ByteArrayOutputStream output = new ByteArrayOutputStream()) {
      xmlFragmentTransformer.transform(new DOMSource(node), new StreamResult(output));
      return output.toByteArray();
    }
    catch (final IOException e) {
      throw new UncheckedIOException("Failed to transform XML node to bytes", e);
    }
    catch (final TransformerException e) {
      throw new DOMException(DOMException.NOT_SUPPORTED_ERR, "Failed to transform XML node to bytes");
    }
  }

  /**
   * Get IssuerSerial data according to RFC5035.
   *
   * @param cert certificate to extract IssuerSerial from
   * @return bytes of DER encoded IssuerSerial according to RFC5035
   * @throws IOException error parsing certificate
   * @throws CertificateEncodingException error parsing certificate
   */
  @Nonnull
  public static byte[] getRfc5035IssuerSerialBytes(@Nonnull final X509Certificate cert)
      throws IOException, CertificateEncodingException {
    return getRfc5035IssuerAndSerial(cert).getEncoded("DER");
  }

  @Nonnull
  private static IssuerSerial getRfc5035IssuerAndSerial(@Nonnull final X509Certificate sigCert)
      throws CertificateEncodingException, IOException {
    final X500Name issuerX500Name = new X509CertificateHolder(sigCert.getEncoded()).getIssuer();
    return new IssuerSerial(new GeneralNames(new GeneralName(issuerX500Name)), sigCert.getSerialNumber());
  }

  @Nonnull
  private Element getUpdatedAdesElement(@Nonnull final QualifyingProperties qualifyingProperties) throws JAXBException {
    final ObjectType newAdesObject = dsObjectFactory.createObjectType();
    newAdesObject.getContent().add(JAXBMarshaller.marshall(qualifyingProperties).getDocumentElement());
    return JAXBMarshaller.marshallNonRootElement(dsObjectFactory.createObject(newAdesObject))
        .getDocumentElement();
  }

  @Nullable
  private QualifyingProperties getQualifyingProperties(@Nonnull final Element adesElement) throws JAXBException {
    final NodeList objectNodeList = adesElement.getChildNodes();
    for (int i = 0; i < objectNodeList.getLength(); i++) {
      final Node child = objectNodeList.item(i);
      if (child instanceof Element) {
        final Element elm = (Element) child;
        if (XadesQualifyingProperties.LOCAL_NAME.equals(elm.getLocalName())) {
          return JAXBUnmarshaller.unmarshall(elm, QualifyingProperties.class);
        }
      }
    }
    return null;
  }

}
