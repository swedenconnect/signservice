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

package se.swedenconnect.signservice.signature.tbsdata.impl;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.binding.xmldsig.*;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.parser.XMLParserException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.xml.XadesQualifyingProperties;
import se.idsec.signservice.xml.DOMUtils;
import se.idsec.signservice.xml.InternalXMLException;
import se.idsec.signservice.xml.JAXBMarshaller;
import se.idsec.signservice.xml.JAXBUnmarshaller;
import se.swedenconnect.schemas.etsi.xades_1_3_2.*;
import se.swedenconnect.security.algorithms.MessageDigestAlgorithm;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.signature.AdESObject;
import se.swedenconnect.signservice.signature.AdESType;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.impl.DefaultAdESObject;
import se.swedenconnect.signservice.signature.tbsdata.TBSProcessingData;

import javax.annotation.Nonnull;
import javax.xml.bind.JAXBException;
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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

/**
 * XML Data to be signed processor
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
   * Default canonicalization algorithm
   *
   * @param defaultCanonicalizationAlgorithm set default canonicalization algorithm
   */
  @Setter private String defaultCanonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";

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
    TransformerFactory transformerFactory = TransformerFactory.newInstance();
    try {
      xmlFragmentTransformer = transformerFactory.newTransformer();
      xmlFragmentTransformer.setOutputProperty("omit-xml-declaration", "yes");
    }
    catch (TransformerConfigurationException e) {
      e.printStackTrace();
    }

  }

  /**
   * Constructor that allows setting of supported processing rules
   *
   * @param supportedProcessingRules list of supported processing rules for this TBS data processor
   */
  public XMLTBSDataProcessor(List<String> supportedProcessingRules) {
    super(supportedProcessingRules);
  }

  /**
   * Constructor for this XML TBS data processor with default settings
   */
  public XMLTBSDataProcessor() {
    super(new ArrayList<>());
  }

  @Override public TBSProcessingData getTBSData(@Nonnull final RequestedSignatureTask signatureTask,
    @Nonnull final PkiCredential signingCredential,
    @Nonnull final SignatureAlgorithm signatureAlgorithm) throws SignatureException {

    // Check and collect data
    checkIndata(signatureTask, signingCredential, signatureAlgorithm);
    defaultProcessingRuleCheck(signatureTask.getProcessingRulesUri());
    byte[] tbsBytes = signatureTask.getTbsData();
    SignatureType signatureType = signatureTask.getSignatureType();
    if (!signatureType.equals(SignatureType.XML)) {
      throw new SignatureException("Signature type must be XML");
    }
    AdESType adESType = signatureTask.getAdESType();
    AdESObject adESObject = signatureTask.getAdESObject();
    boolean xades = AdESType.BES.equals(adESType) || AdESType.EPES.equals(adESType);
    log.debug("XAdES signature = {}", xades);

    // Process TBS data
    try {

      if (xades) {
        if (adESObject == null) {
          throw new SignatureException("the AdESObject must not be null when the signature is an AdES XML signature");
        }
        String signatureId = Optional.ofNullable(adESObject.getSignatureId())
          .orElseThrow(() -> new SignatureException("Signature ID must not be null in a XAdES signature"));
        byte[] adesObjectBytes = adESObject.getObjectBytes();
        XadesQualifyingProperties xadesObject;
        if (adesObjectBytes == null) {
          xadesObject = XadesQualifyingProperties.createXadesQualifyingProperties();
        }
        else {
          Document adesObjectDocument = DOMUtils.bytesToDocument(adesObjectBytes);
          ObjectType adesObjectType = JAXBUnmarshaller.unmarshall(adesObjectDocument, ObjectType.class);
          xadesObject = new XadesQualifyingProperties(adesObjectType);
        }

        Element adesElement = xadesObject.getAdesElement();
        QualifyingProperties qualifyingProperties = Optional.ofNullable(getQualifyingProperties(adesElement)).orElseThrow(() ->
          new SignatureException("Failed to obtain QualifyingProperties from provided AdES object"));
        String ref = addSigningCertRef(signingCredential.getCertificate(), qualifyingProperties, signatureId,
          signatureAlgorithm);
        Element updatedAdesElement = getUpdatedAdesElement(qualifyingProperties);
        byte[] updatedAdesObjectBytes = nodeToBytes(updatedAdesElement);
        byte[] updatedTbsData = getUpdatedTbsData(tbsBytes, updatedAdesElement, signatureAlgorithm, ref);

        AdESObject updatedAdesObject = new DefaultAdESObject(signatureId, updatedAdesObjectBytes);

        return TBSProcessingData.builder()
          .processingRules(signatureTask.getProcessingRulesUri())
          .adESObject(updatedAdesObject)
          .tBSBytes(updatedTbsData)
          .build();
      }
      else {
        return TBSProcessingData.builder()
          .processingRules(signatureTask.getProcessingRulesUri())
          .tBSBytes(tbsBytes)
          .build();
      }
    }
    catch (DocumentProcessingException | JAXBException | DatatypeConfigurationException | NoSuchAlgorithmException |
      CertificateEncodingException | IOException | XMLParserException | InvalidCanonicalizerException |
      CanonicalizationException | ParserConfigurationException | SAXException e) {
      throw new SignatureException("Unable to parse data to be signed in request", e);
    }
  }

  /**
   * Adds signer certificate reference to AdES object
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
  private String addSigningCertRef(X509Certificate certificate, QualifyingProperties qualifyingProperties,
    String signatureId, SignatureAlgorithm signatureAlgorithm)
    throws DatatypeConfigurationException, NoSuchAlgorithmException, CertificateEncodingException, IOException {

    // Set the expected signature ID ref
    qualifyingProperties.setTarget("#" + signatureId);

    // Add or create SignedProperties
    if (!qualifyingProperties.isSetSignedProperties()) {
      qualifyingProperties.setSignedProperties(xadesObjectFactory.createSignedProperties());
    }
    SignedProperties signedProperties = qualifyingProperties.getSignedProperties();
    String signedPropertiesId = signedProperties.getId();
    if (signedPropertiesId == null) {
      signedPropertiesId = "xades-id-" + new BigInteger(128, RNG).toString(16);
      signedProperties.setId(signedPropertiesId);
    }
    // Add or create SignedSignatureProperties
    if (!signedProperties.isSetSignedSignatureProperties()) {
      signedProperties.setSignedSignatureProperties(xadesObjectFactory.createSignedSignatureProperties());
    }
    SignedSignatureProperties signedSignatureProperties = signedProperties.getSignedSignatureProperties();
    // Set signing time to current time
    XMLGregorianCalendar signingTime = DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar());
    signedSignatureProperties.setSigningTime(signingTime);
    if (signedSignatureProperties.isSetSigningCertificate()) {
      // There is an old outdated certificate reference deltet it
      signedSignatureProperties.setSigningCertificate(null);
      log.debug("AdES object from sign request contained V1 certificate reference. This was deleted");
    }

    // Hash certificate
    MessageDigestAlgorithm messageDigestAlgorithm = signatureAlgorithm.getMessageDigestAlgorithm();
    MessageDigest md = MessageDigest.getInstance(messageDigestAlgorithm.getJcaName());
    byte[] certDigest = md.digest(certificate.getEncoded());

    // Create and set a new instance of signingCertificateV2
    signedSignatureProperties.setSigningCertificateV2(xadesObjectFactory.createSigningCertificateV2());
    SigningCertificateV2 signingCertificateV2 = signedSignatureProperties.getSigningCertificateV2();
    List<CertIDTypeV2> certs = signingCertificateV2.getCerts();
    CertIDTypeV2 certIDTypeV2 = xadesObjectFactory.createCertIDTypeV2();
    DigestAlgAndValueType digestAlgAndValueType = xadesObjectFactory.createDigestAlgAndValueType();
    DigestMethodType digestMethodType = dsObjectFactory.createDigestMethodType();
    digestMethodType.setAlgorithm(messageDigestAlgorithm.getUri());
    digestAlgAndValueType.setDigestMethod(digestMethodType);
    digestAlgAndValueType.setDigestValue(certDigest);
    certIDTypeV2.setCertDigest(digestAlgAndValueType);
    if (includeIssuerSerial){
      byte[] issuerSerial = getRfc5035IssuerSerialBytes(certificate);
      certIDTypeV2.setIssuerSerialV2(issuerSerial);
    }
    certs.add(certIDTypeV2);

    return signedPropertiesId;
  }

  /**
   * Updates the SignedInfo based on an updated XAdES object
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
  private byte[] getUpdatedTbsData(final byte[] tbsBytes, final Element updatedAdesElement,
    final SignatureAlgorithm signatureAlgorithm, final String ref)
    throws JAXBException, SignatureException, XMLParserException, InvalidCanonicalizerException,
    CanonicalizationException, ParserConfigurationException, IOException, SAXException, NoSuchAlgorithmException {

    Document tbsDocument = DOMUtils.bytesToDocument(tbsBytes);
    SignedInfoType signedInfo = JAXBUnmarshaller.unmarshall(tbsDocument, SignedInfoType.class);

    List<ReferenceType> referenceList = signedInfo.getReference();
    if (referenceList == null || referenceList.isEmpty()) {
      // We do require at least one reference to signed data
      throw new SignatureException("Input SignedInfo does not contain any reference data");
    }
    List<ReferenceType> xadesReferenceList = referenceList.stream()
      .filter(referenceType -> SIGNED_PROPERTIES_TYPE.equalsIgnoreCase(referenceType.getType()))
      .collect(Collectors.toList());

    if (xadesReferenceList.size() > 1) {
      // We do not allow more than one XAdES SignedProperties reference
      throw new SignatureException("SignedInfo has more than one XAdES reference");
    }

    if (xadesReferenceList.isEmpty()) {
      ReferenceType newXadesRef = dsObjectFactory.createReferenceType();
      newXadesRef.setType(SIGNED_PROPERTIES_TYPE);
      referenceList.add(newXadesRef);
    }

    ReferenceType xadesReference = referenceList.stream()
      .filter(referenceType -> SIGNED_PROPERTIES_TYPE.equalsIgnoreCase(referenceType.getType()))
      .findFirst().orElseThrow();

    xadesReference.setURI("#" + ref);
    // Set digest method
    DigestMethodType digestMethodType = dsObjectFactory.createDigestMethodType();
    digestMethodType.setAlgorithm(signatureAlgorithm.getMessageDigestAlgorithm().getUri());
    xadesReference.setDigestMethod(digestMethodType);

    // Set digest value
    Node signedPropertiesNode = updatedAdesElement.getElementsByTagNameNS(XADES_XML_NS,
      SIGNED_PROPERTIES_ELEMENT_NAME).item(0);
    byte[] signedPropertyBytes = getCanonicalXml(nodeToBytes(signedPropertiesNode),
      defaultCanonicalizationAlgorithm);
    MessageDigest md = MessageDigest.getInstance(signatureAlgorithm.getMessageDigestAlgorithm().getJcaName());
    byte[] signedPropertyHash = md.digest(signedPropertyBytes);
    xadesReference.setDigestValue(signedPropertyHash);

    //Set transform algo
    TransformType transform = dsObjectFactory.createTransformType();
    transform.setAlgorithm(defaultCanonicalizationAlgorithm);
    TransformsType transforms = dsObjectFactory.createTransformsType();
    transforms.getTransform().add(transform);
    xadesReference.setTransforms(transforms);

    //Done updating SignedInfo. Finally, transform SignedInfo to bytes
    CanonicalizationMethodType canonicalizationMethodType = Optional.ofNullable(
        signedInfo.getCanonicalizationMethod())
      .orElseThrow(() -> new SignatureException(
        "SignedInfo has no canonicalization algorithm element"));
    String canonicalizationAlgorithm = Optional.ofNullable(canonicalizationMethodType.getAlgorithm())
      .orElseThrow(() -> new SignatureException(
        "SignedInfo has no canonicalization algorithm"));
    return getCanonicalXml(nodeToBytes(JAXBMarshaller.marshallNonRootElement(dsObjectFactory.createSignedInfo(signedInfo)).getDocumentElement()),
      canonicalizationAlgorithm);
  }

  /**
   * Get canonical XML from xml input
   *
   * @param xmlBytes XML data to canonicalize
   * @param canonicalizationAlgo canonicalization algorithm
   * @return canonical XML
   * @throws InvalidCanonicalizerException bad canonicalization algorithm
   * @throws IOException data parsing error
   * @throws CanonicalizationException canonicalization error
   * @throws XMLParserException error parsing XML input
   */
  public static byte[] getCanonicalXml(@Nonnull final byte[] xmlBytes, @Nonnull final String canonicalizationAlgo) throws
    InvalidCanonicalizerException, IOException, CanonicalizationException, XMLParserException {
    Objects.requireNonNull(xmlBytes, "XML Bytes to canonicalize must not be null");
    Objects.requireNonNull(canonicalizationAlgo, "Canonicalization algorithm must be specified");
    Canonicalizer canon = Canonicalizer.getInstance(canonicalizationAlgo);
    try(ByteArrayOutputStream os = new ByteArrayOutputStream()){
      canon.canonicalize(xmlBytes, os, true);
      return os.toByteArray();
    }
  }

  /**
   * Transforms an XML node to bytes without XML declaration
   * @param node node to transform to byte
   * @return byte representation of the XML node without XML declaration
   */
  public static byte[] nodeToBytes(Node node) {
    try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
      xmlFragmentTransformer.transform(new DOMSource(node), new StreamResult(output));
      return output.toByteArray();
    }
    catch (TransformerException | IOException e) {
      throw new InternalXMLException("Failed to transform XML node to bytes", e);
    }
  }

  /**
   * Get IssuerSerial data according to RFC5035
   *
   * @param cert certificate to extract IssuerSerial from
   * @return bytes of DER encoded IssuerSerial according to RFC5035
   * @throws IOException error parsing certificate
   * @throws CertificateEncodingException error parsing certificate
   */
  public static byte[] getRfc5035IssuerSerialBytes(X509Certificate cert)
    throws IOException, CertificateEncodingException {
    return getRfc5035IssuerAndSerial(cert).getEncoded("DER");
  }

  private static IssuerSerial getRfc5035IssuerAndSerial(X509Certificate sigCert)
    throws CertificateEncodingException, IOException {
    X500Name issuerX500Name = (new X509CertificateHolder(sigCert.getEncoded())).getIssuer();
    GeneralName generalName = new GeneralName(issuerX500Name);
    GeneralNames generalNames = new GeneralNames(generalName);
    BigInteger serialNumber = sigCert.getSerialNumber();
    return new IssuerSerial(generalNames, serialNumber);
  }

  private Element getUpdatedAdesElement(QualifyingProperties qualifyingProperties) throws JAXBException {
    ObjectType newAdesObject = dsObjectFactory.createObjectType();
    newAdesObject.getContent().add(JAXBMarshaller.marshall(qualifyingProperties).getDocumentElement());
    return JAXBMarshaller.marshallNonRootElement(dsObjectFactory.createObject(newAdesObject))
      .getDocumentElement();
  }


  private QualifyingProperties getQualifyingProperties(Element adesElement) throws JAXBException {
    NodeList objectNodeList = adesElement.getChildNodes();
    for (int i = 0; i < objectNodeList.getLength(); i++) {
      Node child = objectNodeList.item(i);
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
