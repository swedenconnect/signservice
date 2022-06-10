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

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.security.algorithms.MessageDigestAlgorithm;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.signature.AdESType;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.tbsdata.TBSProcessingData;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * PDF TBS Data processor that parse input data to be signed and produce the actual data to be signed
 * by the signing service. This involves updating the CMS signed attributes with relevant data including:
 *
 * <ul>
 *   <li>Removing any signing time attribute in PAdES signatures</li>
 *   <li>Adding or replacing any CMS algorithm protection attribute</li>
 *   <li>Updating any ESSCertID or ESSCertIDV2 signing certificate attibutes</li>
 * </ul>
 */
@Slf4j
public class PDFTBSDataProcessor extends AbstractTBSDataProcessor {

  /**
   * Constructor for this PDF TBS data processor with default settings
   */
  public PDFTBSDataProcessor() {
    super(new ArrayList<>());
  }

  /**
   * Constructor that allows setting of supported processing rules
   *
   * @param supportedProcessingRules list of supported processing rules for this TBS data processor
   */
  public PDFTBSDataProcessor(List<String> supportedProcessingRules) {
    super(supportedProcessingRules);
  }

  @Override public TBSProcessingData getTBSData(@Nonnull final RequestedSignatureTask signatureTask,
    @Nonnull final PkiCredential signingCredential,
    @Nonnull final SignatureAlgorithm signatureAlgorithm) throws SignatureException {

    // Check and collect data
    checkIndata(signatureTask,signingCredential, signatureAlgorithm);
    defaultProcessingRuleCheck(signatureTask.getProcessingRulesUri());
    byte[] tbsBytes = signatureTask.getTbsData();
    SignatureType signatureType = signatureTask.getSignatureType();
    if (!signatureType.equals(SignatureType.PDF)) {
      throw new SignatureException("Signature type must be PDF");
    }
    AdESType adESType = signatureTask.getAdESType();
    boolean pades = AdESType.BES.equals(adESType) || AdESType.EPES.equals(adESType);
    log.debug("PAdES signature = {}", pades);

    // Process TBS data
    try {
      List<Attribute> signedAttributes = parseSignedAttributeBytes(tbsBytes);
      log.debug("Processing {} input signed attributes", signedAttributes.size());

      // Check that contentType attribute is present
      Attribute contentTypeAttr = signedAttributes.stream()
        .filter(attribute -> CMSAttributes.contentType.equals(attribute.getAttrType()))
        .findFirst()
        .orElseThrow(() -> new SignatureException("Signed attributes input has no contentType attribute"));
      try {
        ASN1ObjectIdentifier contentType = ASN1ObjectIdentifier.getInstance(
          contentTypeAttr.getAttrValues().getObjectAt(0));
        if (!PKCSObjectIdentifiers.data.equals(contentType)) {
          throw new SignatureException("Illegal content type in signed attributes input");
        }
      }
      catch (Exception ex) {
        throw new SignatureException("Illegal attribute data in content type attributes in signed attributes input");
      }

      if (!isAttributePresent(CMSAttributes.messageDigest, signedAttributes)) {
        throw new SignatureException("Signed attributes input has no message digest");
      }
      log.debug("TBS input has required signed attributes");

      // Test signing time
      if (isAttributePresent(CMSAttributes.signingTime, signedAttributes)) {
        if (pades) {
          if (strictProcessing) {
            throw new SignatureException("Signing time is not allowed in PAdES requests in strict processing");
          }
          // remove any signed attributes with signing time
          signedAttributes = signedAttributes.stream()
            .filter(attribute -> !CMSAttributes.signingTime.equals(attribute.getAttrType()))
            .collect(Collectors.toList());
          log.debug("Removed existing signing time attribute as this is not allowed in PAdES");
        }
        else {
          // This is not a PAdES signature. Signing time attribute is provided. Set current time
          signedAttributes = replaceAttribute(signedAttributes, CMSAttributes.signingTime,
            getSigningTimeAttribute(null));
          log.debug("Replacing signing time attribute with current time from system clock");
        }
      }

      // Add or replace CMS algorithm protection
      Attribute cmsAlgoProtection = getCMSAlgoProtection(signatureAlgorithm);
      if (isAttributePresent(CMSAttributes.cmsAlgorithmProtect, signedAttributes)) {
        signedAttributes = replaceAttribute(signedAttributes, CMSAttributes.cmsAlgorithmProtect, cmsAlgoProtection);
        log.debug("Replaced existing CMS algorithm protection attribute");
      }
      else {
        signedAttributes.add(cmsAlgoProtection);
        log.debug("Added CMS algorithm protection attribute");
      }

      // Add signed certificate reference if PAdES or if the signing certificate attribute is present
      boolean hasSigningCertAttribute =
        isAttributePresent(PKCSObjectIdentifiers.id_aa_signingCertificate, signedAttributes)
          || isAttributePresent(PKCSObjectIdentifiers.id_aa_signingCertificateV2, signedAttributes);
      if (pades || hasSigningCertAttribute) {
        log.debug("Setting signed certificate attribute for PAdES");
        // Remove any previously existing signed certificate attribute
        if (hasSigningCertAttribute) {
          log.debug("Removing present ESSCertID attribute from requested TBS data");
          signedAttributes = removeAttributes(List.of(
              PKCSObjectIdentifiers.id_aa_signingCertificate,
              PKCSObjectIdentifiers.id_aa_signingCertificateV2),
            signedAttributes);
        }
        //Add a new signed certificate attribute
        signedAttributes.add(getSignedCertAttr(signatureAlgorithm.getMessageDigestAlgorithm(),
          signingCredential.getCertificate(), includeIssuerSerial));
      }

      // Assemble and return data to be signed
      return TBSProcessingData.builder()
        .processingRules(signatureTask.getProcessingRulesUri())
        .tBSBytes(consolidateTBSData(signedAttributes))
        .build();
    }
    catch (IOException | NoSuchAlgorithmException | CertificateException e) {
      throw new SignatureException("Unable to parse data to be signed in request", e);
    }
  }

  public static byte[] consolidateTBSData(@Nonnull final List<Attribute> signedAttributes) throws IOException {
    Objects.requireNonNull(signedAttributes, "Signed attributes must not be null");
    ASN1EncodableVector aev = new ASN1EncodableVector();
    signedAttributes.forEach(aev::add);
    return new DERSet(aev).getEncoded("DER");
  }

  public static List<Attribute> removeAttributes(@Nullable final List<ASN1ObjectIdentifier> attrOidList,
    @Nonnull final List<Attribute> attributeList) {
    Objects.requireNonNull(attributeList, "Attribute list must not be null");

    if (attrOidList == null) {
      return attributeList;
    }
    return attributeList.stream()
      .filter(attribute -> !attrOidList.contains(attribute.getAttrType()))
      .collect(Collectors.toList());
  }

  /**
   * Get signer certificate attribute
   *
   * @param digestAlgo the digest algorithm used to hash the certificate
   * @param certificate the certificate
   * @param includeIssuerSerial true if the signing certificate attribute should include IssuerSerial data
   * @return CMS Signed certificate attribute (V1 if digest is SHA-1 else V2)
   * @throws NoSuchAlgorithmException algorithm is not supported
   * @throws IOException error in parsed data or using the selected digest method
   * @throws CertificateException error in provided certificate
   */
  public static Attribute getSignedCertAttr(@Nonnull final MessageDigestAlgorithm digestAlgo,
    @Nonnull final X509Certificate certificate, final boolean includeIssuerSerial) throws
    NoSuchAlgorithmException, IOException, CertificateException {

    Objects.requireNonNull(digestAlgo, "Digest algorithm must not be null");
    Objects.requireNonNull(certificate, "Signing certificate must not be null");

    MessageDigest md = MessageDigest.getInstance(digestAlgo.getJcaName());
    md.update(certificate.getEncoded());
    byte[] certHash = md.digest();

    ASN1ObjectIdentifier signedCertOid;
    ASN1Object signingCertObject;
    IssuerSerial issuerSerial = includeIssuerSerial ? getIssuerSerial(certificate) : null;

    if (OIWObjectIdentifiers.idSHA1.equals(digestAlgo.getAlgorithmIdentifier().getAlgorithm())) {
      signedCertOid = PKCSObjectIdentifiers.id_aa_signingCertificate;
      signingCertObject = new SigningCertificate(new ESSCertID(certHash, issuerSerial));
      log.warn("Adding ESSCertID based on SHA-1");
    }
    else {
      signedCertOid = PKCSObjectIdentifiers.id_aa_signingCertificateV2;
      signingCertObject = new SigningCertificateV2(
        new ESSCertIDv2(digestAlgo.getAlgorithmIdentifier(), certHash, issuerSerial));
      log.debug("Adding ESSCertIDV2 signed certificate attribute");
    }

    ASN1EncodableVector aev = new ASN1EncodableVector(1);
    aev.add(signingCertObject);
    return new Attribute(signedCertOid, new DERSet(aev));
  }

  /**
   * Get Issuer Serial data from an X.509 certificate
   *
   * @param certificate the certificate to extract issuer serial from
   * @return {@link IssuerSerial}
   * @throws CertificateEncodingException error parsing the certificate
   * @throws IOException other error parsing input data
   */
  public static IssuerSerial getIssuerSerial(@Nonnull final X509Certificate certificate)
    throws CertificateEncodingException, IOException {
    Objects.requireNonNull(certificate, "Certificate must not be null");
    return new IssuerSerial(
      new GeneralNames(new GeneralName(
        new X509CertificateHolder(certificate.getEncoded()).getIssuer())),
      certificate.getSerialNumber());
  }

  /**
   * Get a CMS Algo protection attribute for the selected algorithm
   *
   * @param signatureAlgorithm signature algorithm
   * @return CMS algorithm protection attribute
   * @throws IOException error parsing input data
   */
  public static Attribute getCMSAlgoProtection(@Nonnull final SignatureAlgorithm signatureAlgorithm)
    throws IOException {
    Objects.requireNonNull(signatureAlgorithm, "Signature algorithm must not be null");
    ASN1EncodableVector attrSet = new ASN1EncodableVector();
    ASN1EncodableVector algoIdSeq = new ASN1EncodableVector();

    algoIdSeq.add(signatureAlgorithm.getMessageDigestAlgorithm().getAlgorithmIdentifier());

    switch (signatureAlgorithm.getKeyType()) {
    case "EC":
    case "RSA":
      algoIdSeq.add(new DERTaggedObject(false, 1, signatureAlgorithm.getAlgorithmIdentifier()));
      break;
    default:
      throw new IOException("Illegal signature algorithm key type");
    }
    attrSet.add(new DERSequence(algoIdSeq));
    return new Attribute(CMSAttributes.cmsAlgorithmProtect, new DERSet(attrSet));
  }

  /**
   * Replace an attribute of specified type with the provided attribute. Replacement only takes place
   * if the provided list contains the requested attribute.
   *
   * @param signedAttributes the collection of signed attributes to be modified
   * @param attributeOid the OID of the attribute to be replaced
   * @param replacementAttribute replacement attribute
   * @return list of signed attributes with the replaced attribute if such attribute existed
   */
  public static List<Attribute> replaceAttribute(@Nonnull final List<Attribute> signedAttributes,
    @Nonnull final ASN1ObjectIdentifier attributeOid, @Nonnull final Attribute replacementAttribute) {
    Objects.requireNonNull(signedAttributes, "Signed attributes must not be null");
    Objects.requireNonNull(attributeOid, "Attribute OID must not be null");
    Objects.requireNonNull(replacementAttribute, "Replacement attribute must not be null");

    List<Attribute> modifiedAttrList = new ArrayList<>();
    for (Attribute attribute : signedAttributes) {
      if (attributeOid.equals(attribute.getAttrType())) {
        modifiedAttrList.add(replacementAttribute);
      }
      else {
        modifiedAttrList.add(attribute);
      }
    }
    return modifiedAttrList;
  }

  /**
   * Check if a particular attribute is present in the list of attriubtes
   *
   * @param attributeOid target attribute OID
   * @param attributeList list of attributes to examine
   * @return true if the target attribute OID is present in the attribute list;
   */
  public static boolean isAttributePresent(final ASN1ObjectIdentifier attributeOid,
    final List<Attribute> attributeList) {
    if (attributeOid == null || attributeList == null) {
      return false;
    }
    return attributeList.stream()
      .anyMatch(attribute -> attributeOid.equals(attribute.getAttrType()));
  }

  /**
   * Get signing time attribute for a specific data
   *
   * @param date time to put into the attribute or null for current time
   * @return signing time attribute
   */
  public static Attribute getSigningTimeAttribute(@Nullable Date date) {
    date = Optional.ofNullable(date).orElse(new Date());
    ASN1EncodableVector aev = new ASN1EncodableVector(1);
    aev.add(new ASN1UTCTime(date));
    return new Attribute(CMSAttributes.signingTime, new DERSet(aev));
  }

  /**
   * Parse CMS signed attributes.
   *
   * @param signedAttributeBytes CMS signed attributes bytes
   * @return the list of attributes in signed attributes
   * @throws IOException if the input data contains illegal ASN.1
   */
  public static List<Attribute> parseSignedAttributeBytes(byte[] signedAttributeBytes) throws IOException {
    List<Attribute> signedAttributes = new ArrayList<>();
    try (final ASN1InputStream ain = new ASN1InputStream(signedAttributeBytes)) {
      ASN1Set attrSet = ASN1Set.getInstance(ain.readObject());
      for (int i = 0; i < attrSet.size(); i++) {
        signedAttributes.add(Attribute.getInstance(attrSet.getObjectAt(i)));
      }
      return signedAttributes;
    }
    catch (Exception e) {
      throw (e instanceof IOException) ? (IOException) e : new IOException(e);
    }
  }

  /**
   * Get the signing time in CMS signed attributes data if present.
   *
   * @param signedAttributes CMS signed attributes
   * @return signing time if present or null
   * @throws IOException if the input data contains illegal ASN.1
   */
  public static Date getCmsSigningTime(List<Attribute> signedAttributes) throws IOException {
    for (Attribute attr : signedAttributes) {
      if (CMSAttributes.signingTime.equals(attr.getAttrType())) {
        try {
          ASN1Encodable[] attributeValues = attr.getAttributeValues();
          ASN1UTCTime time = ASN1UTCTime.getInstance(attributeValues[0]);
          return time.getAdjustedDate();
        }
        catch (ParseException e) {
          throw new IOException("Illegal date in signed attributes", e);
        }
      }
    }
    return null;
  }

}
