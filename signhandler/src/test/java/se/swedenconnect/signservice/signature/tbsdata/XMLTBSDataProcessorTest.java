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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.MessageDigest;
import java.security.SignatureException;
import java.time.Instant;
import java.util.Date;

import org.apache.xml.security.binding.xmldsig.ObjectType;
import org.apache.xml.security.binding.xmldsig.ReferenceType;
import org.apache.xml.security.binding.xmldsig.SignedInfoType;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.xml.DOMUtils;
import se.swedenconnect.schemas.etsi.xades_1_3_2.CertIDTypeV2;
import se.swedenconnect.schemas.etsi.xades_1_3_2.QualifyingProperties;
import se.swedenconnect.schemas.etsi.xades_1_3_2.SignedSignatureProperties;
import se.swedenconnect.schemas.etsi.xades_1_3_2.SigningCertificate;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.signature.AdESType;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.impl.DefaultAdESObject;
import se.swedenconnect.signservice.signature.impl.DefaultRequestedSignatureTask;
import se.swedenconnect.signservice.signature.signer.TestAlgorithms;
import se.swedenconnect.signservice.signature.signer.TestCredentials;
import se.swedenconnect.signservice.signature.testutils.TestData;
import se.swedenconnect.signservice.signature.testutils.TestUtils;
import se.swedenconnect.xml.jaxb.JAXBMarshaller;
import se.swedenconnect.xml.jaxb.JAXBUnmarshaller;

/**
 * XML To Be Signed data processor tests
 */
@Slf4j
class XMLTBSDataProcessorTest {

  static PkiCredential testECCredential;
  static PkiCredential testRSACredential;

  static String tbsDataNoRef = getNoRefSignedIfo();

  static String reqAdesObjectWithV1CertRef = getV1CertRefAdesObject();

  static XMLTBSDataProcessor mainTbsDataprocessor;
  static XMLTBSDataProcessor strictTbsDataprocessor;
  static XMLTBSDataProcessor issuerSerialTbsDataprocessor;

  @BeforeAll
  static void setUp() {
    org.apache.xml.security.Init.init();
    testECCredential = new BasicCredential(TestCredentials.ecCertificate, TestCredentials.privateECKey);
    testRSACredential = new BasicCredential(TestCredentials.rsaCertificate, TestCredentials.privateRSAKey);

    mainTbsDataprocessor = new XMLTBSDataProcessor();
    strictTbsDataprocessor = new XMLTBSDataProcessor();
    strictTbsDataprocessor.setStrictProcessing(true);
    issuerSerialTbsDataprocessor = new XMLTBSDataProcessor();
    issuerSerialTbsDataprocessor.setIncludeIssuerSerial(true);

  }

  @Test
  void getTBSData() throws Exception {

    testCase(TestInput.builder()
      .description("Default request with input AdES object")
      .sigType(SignatureType.XML).adESType(AdESType.BES).processingRules(null)
      .tbsData(TestData.tbsDataXmlAdes01)
      .requestAdesObject(TestData.fixXAdESSigTime(TestData.reqAdesObject01))
      .signatureId(TestData.signatureId01)
      .credential(testRSACredential)
      .signatureAlgorithm(TestAlgorithms.getRsaSha256())
      .build());

    testCase(TestInput.builder()
      .description("RSA signing request with wrong algorithm")
      .sigType(SignatureType.XML).adESType(AdESType.BES).processingRules(null)
      .tbsData(TestData.tbsDataXmlAdes01)
      .requestAdesObject(TestData.fixXAdESSigTime(TestData.reqAdesObject01))
      .signatureId(TestData.signatureId01)
      .credential(testRSACredential)
      .signatureAlgorithm(TestAlgorithms.getRsaPssSha384())
      .exception(SignatureException.class)
      .build());

    testCase(TestInput.builder()
      .description("Default request with no input AdES object")
      .sigType(SignatureType.XML).adESType(AdESType.BES).processingRules(null)
      .tbsData(TestData.tbsDataXmlNoAdes)
      .signatureId(TestData.signatureId01)
      .credential(testECCredential)
      .signatureAlgorithm(TestAlgorithms.getEcdsaSha256())
      .build());

    testCase(TestInput.builder()
      .description("Include issuer serial")
      .sigType(SignatureType.XML).adESType(AdESType.BES).processingRules(null)
      .tbsData(TestData.tbsDataXmlNoAdes)
      .signatureId(TestData.signatureId01)
      .credential(testECCredential)
      .signatureAlgorithm(TestAlgorithms.getEcdsaSha256())
      .tbsDataProcessor(issuerSerialTbsDataprocessor)
      .includeIssuerSerial(true)
      .build());

    testCase(TestInput.builder()
      .description("No AdES Signature")
      .sigType(SignatureType.XML).adESType(null).processingRules(null)
      .tbsData(TestData.tbsDataXmlNoAdes)
      .credential(testECCredential)
      .signatureAlgorithm(TestAlgorithms.getEcdsaSha256())
      .build());

    testCase(TestInput.builder()
      .description("Remove V1 Signing Certificate ref")
      .sigType(SignatureType.XML).adESType(AdESType.BES).processingRules(null)
      .tbsData(TestData.tbsDataXmlAdes01)
      .requestAdesObject(TestData.fixXAdESSigTime(reqAdesObjectWithV1CertRef))
      .signatureId(TestData.signatureId01)
      .credential(testRSACredential)
      .signatureAlgorithm(TestAlgorithms.getRsaSha256())
      .build());

    testCase(TestInput.builder()
      .description("Request with no references in signed data")
      .sigType(SignatureType.XML).adESType(AdESType.BES)
      .tbsData(tbsDataNoRef)
      .credential(testECCredential)
      .signatureId(TestData.signatureId01)
      .signatureAlgorithm(TestAlgorithms.getEcdsaSha256())
      .exception(SignatureException.class)
      .build());

    // Error test cases
    testCase(TestInput.builder()
      .description("Null Requested Signature task")
      .sigType(SignatureType.XML)
      .credential(testECCredential)
      .signatureAlgorithm(TestAlgorithms.getEcdsaSha256())
      .exception(NullPointerException.class)
      .build());

    testCase(TestInput.builder()
      .description("Null Credentials")
      .sigType(SignatureType.XML).adESType(AdESType.BES)
      .tbsData(TestData.tbsDataXmlAdes01)
      .signatureAlgorithm(TestAlgorithms.getEcdsaSha256())
      .exception(NullPointerException.class)
      .build());

    testCase(TestInput.builder()
      .description("Null Signature Algorithm")
      .sigType(SignatureType.XML).adESType(AdESType.BES)
      .tbsData(TestData.tbsDataXmlAdes01)
      .credential(testECCredential)
      .exception(NullPointerException.class)
      .build());

    testCase(TestInput.builder()
      .description("Null TBS data in signature request")
      .sigType(SignatureType.XML).adESType(AdESType.BES)
      .credential(testECCredential)
      .signatureAlgorithm(TestAlgorithms.getEcdsaSha256())
      .exception(SignatureException.class)
      .build());

    testCase(TestInput.builder()
      .description("Null signature type in signature request")
      .adESType(AdESType.BES)
      .tbsData(TestData.tbsDataXmlAdes01)
      .credential(testECCredential)
      .signatureAlgorithm(TestAlgorithms.getEcdsaSha256())
      .exception(SignatureException.class)
      .build());
  }

  @Test void toOldSignningTimeTest() throws Exception {
    Instant signingTime = Instant.now().minusSeconds(250);
    testCase(TestInput.builder()
      .description("Signing time to old")
      .sigType(SignatureType.XML).adESType(AdESType.BES).processingRules(null)
      .tbsData(TestData.tbsDataXmlAdes01)
      .requestAdesObject(TestData.fixXAdESSigTime(TestData.reqAdesObject01, signingTime))
      .signatureId(TestData.signatureId01)
      .credential(testRSACredential)
      .signatureAlgorithm(TestAlgorithms.getRsaSha256())
      .exception(SignatureException.class)
      .build());
  }

  @Test void futureSignningTimeTest() throws Exception {
    Instant signingTime = Instant.now().plusSeconds(50);
    testCase(TestInput.builder()
      .description("Future signing time")
      .sigType(SignatureType.XML).adESType(AdESType.BES).processingRules(null)
      .tbsData(TestData.tbsDataXmlAdes01)
      .requestAdesObject(TestData.fixXAdESSigTime(TestData.reqAdesObject01, signingTime))
      .signatureId(TestData.signatureId01)
      .credential(testRSACredential)
      .signatureAlgorithm(TestAlgorithms.getRsaSha256())
      .exception(SignatureException.class)
      .build());
  }

  void testCase(TestInput input) throws Exception {

    log.info("Running XML TBS data processor test: " + input.description);
    log.info("Requested tbs data:\n{}", TestUtils.base64Print(input.tbsData));
    log.info("Requested AdES data:\n{}", TestUtils.base64Print(input.requestAdesObject));

    XMLTBSDataProcessor tbsDP = input.tbsDataProcessor == null
      ? mainTbsDataprocessor
      : input.getTbsDataProcessor();

    RequestedSignatureTask requestedSignatureTask = input.tbsData == null && input.adESType == null
      ? null
      : getRequestedSignatureTask(input.tbsData, input.sigType, input.adESType, input.signatureId,
      input.requestAdesObject, input.processingRules);

    // Exception test
    if (input.getException() != null) {
      Exception exception = assertThrows(input.exception, () -> tbsDP.processSignTaskData(
        requestedSignatureTask, input.credential.getCertificate(), input.signatureAlgorithm
      ));
      assertTrue(input.exception.isAssignableFrom(exception.getClass()));
      log.info("Caught exception: {}", exception.toString());
      return;
    }

    // Non exception test
    TBSProcessingData tbsData = tbsDP.processSignTaskData(requestedSignatureTask, input.credential.getCertificate(), input.signatureAlgorithm);
    log.info("Result tbs data:\n{}", TestUtils.base64Print(tbsData.getTbsBytes()));
    if (tbsData.getAdesObject() != null) {
      log.info("Result AdES object:\n{}", TestUtils.base64Print(tbsData.getAdesObject().getObjectBytes()));
      log.info("Result AdES object signature ID: {}", tbsData.getAdesObject().getSignatureId());
    }
    else {
      log.info("No result AdES object");
    }

    Document inpTbsDocument = DOMUtils.bytesToDocument(Base64.decode(input.tbsData));
    SignedInfoType inpSignedInfo = JAXBUnmarshaller.unmarshall(inpTbsDocument, SignedInfoType.class);

    Document tbsDocument = DOMUtils.bytesToDocument(tbsData.getTbsBytes());
    SignedInfoType signedInfo = JAXBUnmarshaller.unmarshall(tbsDocument, SignedInfoType.class);

    assertEquals(inpSignedInfo.getCanonicalizationMethod().getAlgorithm(),
      signedInfo.getCanonicalizationMethod().getAlgorithm());
    log.info("Input and output tbs data has matching canonicalization algorithm");
    assertEquals(inpSignedInfo.getSignatureMethod().getAlgorithm(), signedInfo.getSignatureMethod().getAlgorithm());
    log.info("Input and output tbs data has matching signature algorithm");
    assertEquals(input.signatureAlgorithm.getUri(), signedInfo.getSignatureMethod().getAlgorithm());
    log.info("Input and output tbs data has matching signature algorithm");


    if (input.adESType == null) {
      // This is a non AdES test
      assertNull(tbsData.getAdesObject());
      assertArrayEquals(Base64.decode(input.tbsData), tbsData.getTbsBytes());
      log.info("Non AdES request. input data and TBS data match");
      return;
    }

    Document adesObjectDocument = DOMUtils.bytesToDocument(tbsData.getAdesObject().getObjectBytes());
    ObjectType adesObjectType = JAXBUnmarshaller.unmarshall(adesObjectDocument, ObjectType.class);
    Element qpElement = (Element) adesObjectType.getContent().get(0);
    QualifyingProperties qp = JAXBUnmarshaller.unmarshall(qpElement, QualifyingProperties.class);

    assertNull(qp.getSignedProperties().getSignedSignatureProperties().getSigningCertificate());
    log.info("No V1 certificate reference is present");

    CertIDTypeV2 certIDTypeV2 = qp.getSignedProperties()
      .getSignedSignatureProperties()
      .getSigningCertificateV2()
      .getCerts()
      .get(0);
    byte[] issuerSerialV2 = certIDTypeV2.getIssuerSerialV2();
    byte[] certDigest = certIDTypeV2.getCertDigest().getDigestValue();
    if (input.includeIssuerSerial) {
      assertArrayEquals(XMLTBSDataProcessor.getRfc5035IssuerSerialBytes(input.credential.getCertificate()),
        issuerSerialV2);
      log.info("Issuer Serial match");
    }
    else {
      assertNull(issuerSerialV2);
      log.info("Issuer serial is excluded from signing cert V2");
    }
    MessageDigest md = MessageDigest.getInstance(input.signatureAlgorithm.getMessageDigestAlgorithm().getJcaName());
    assertArrayEquals(md.digest(input.credential.getCertificate().getEncoded()), certDigest);
    log.info("Cert digest match");

    String signedPropertiesId = qp.getSignedProperties().getId();
    ReferenceType xadesRef = signedInfo.getReference()
      .stream()
      .filter(referenceType -> ("#" + signedPropertiesId).equals(referenceType.getURI()))
      .findFirst()
      .orElseThrow(() -> new IllegalArgumentException("No reference with signed properties id " + signedPropertiesId));
    log.info("Reference with SignedProperties Id {} found", signedPropertiesId);
    assertEquals(XMLTBSDataProcessor.SIGNED_PROPERTIES_TYPE, xadesRef.getType());
    log.info("XAdES reference is of type {}", XMLTBSDataProcessor.SIGNED_PROPERTIES_TYPE);

    md.reset();
    Node signedPropertiesNode = adesObjectDocument.getElementsByTagNameNS(XMLTBSDataProcessor.XADES_XML_NS,
      XMLTBSDataProcessor.SIGNED_PROPERTIES_ELEMENT_NAME).item(0);
    byte[] signedPropertyBytes = XMLTBSDataProcessor.getCanonicalXml(
      XMLTBSDataProcessor.nodeToBytes(signedPropertiesNode),
      "http://www.w3.org/2001/10/xml-exc-c14n#");

    md.digest(signedPropertyBytes);

    assertArrayEquals(md.digest(signedPropertyBytes), xadesRef.getDigestValue());
    log.info("Digest value match");

    Date adesSignTime = qp.getSignedProperties()
      .getSignedSignatureProperties()
      .getSigningTime()
      .toGregorianCalendar()
      .getTime();
    assertTrue(Math.abs(System.currentTimeMillis() - adesSignTime.getTime()) < 1000);
    log.info("Signing time {} is close enough to current time", adesSignTime);

  }

  private RequestedSignatureTask getRequestedSignatureTask(String tbsDataB64, SignatureType signatureType,
    AdESType adESType, String sigId, String adesObjData, String processingRules) {
    DefaultRequestedSignatureTask signatureTask = new DefaultRequestedSignatureTask();
    signatureTask.setTaskId("id01");
    signatureTask.setSignatureType(signatureType);
    signatureTask.setTbsData(tbsDataB64 == null ? null : Base64.decode(tbsDataB64));
    signatureTask.setAdESType(adESType);
    signatureTask.setAdESObject(new DefaultAdESObject(sigId, adesObjData == null ? null : Base64.decode(adesObjData)));
    signatureTask.setProcessingRulesUri(processingRules);
    return signatureTask;
  }

  @SneakyThrows
  private static String getV1CertRefAdesObject() {
    Document adesObjectDocument = DOMUtils.bytesToDocument(Base64.decode(TestData.reqAdesObject01));
    ObjectType adesObjectType = JAXBUnmarshaller.unmarshall(adesObjectDocument, ObjectType.class);
    Element qpElement = (Element) adesObjectType.getContent().get(0);
    QualifyingProperties qp = JAXBUnmarshaller.unmarshall(qpElement, QualifyingProperties.class);
    SignedSignatureProperties signedSignatureProperties = qp.getSignedProperties().getSignedSignatureProperties();
    signedSignatureProperties.setSigningCertificateV2(null);
    SigningCertificate signingCertificate = XMLTBSDataProcessor.xadesObjectFactory.createSigningCertificate();
    signedSignatureProperties.setSigningCertificate(signingCertificate);

    ObjectType newAdesObject = XMLTBSDataProcessor.dsObjectFactory.createObjectType();
    newAdesObject.getContent().add(JAXBMarshaller.marshall(qp).getDocumentElement());
    byte[] newXadesObjBytes = XMLTBSDataProcessor.nodeToBytes(
      JAXBMarshaller.marshallNonRootElement(XMLTBSDataProcessor.dsObjectFactory.createObject(newAdesObject))
        .getDocumentElement());
    return Base64.toBase64String(newXadesObjBytes);

  }

  @SneakyThrows
  private static String getNoRefSignedIfo() {
    Document inpTbsDocument = DOMUtils.bytesToDocument(Base64.decode(TestData.tbsDataXmlNoAdes));
    SignedInfoType inpSignedInfo = JAXBUnmarshaller.unmarshall(inpTbsDocument, SignedInfoType.class);
    inpSignedInfo.getReference().clear();
    return Base64.toBase64String(XMLTBSDataProcessor.nodeToBytes(JAXBMarshaller.marshallNonRootElement(
      XMLTBSDataProcessor.dsObjectFactory.createSignedInfo(inpSignedInfo)).getDocumentElement()));
  }

  @Data
  @AllArgsConstructor
  @Builder
  static class TestInput {
    String description;
    XMLTBSDataProcessor tbsDataProcessor;
    String tbsData;
    SignatureType sigType;
    AdESType adESType;
    String signatureId;
    String requestAdesObject;
    String processingRules;
    PkiCredential credential;
    SignatureAlgorithm signatureAlgorithm;
    boolean includeIssuerSerial;
    Class<? extends Exception> exception;
  }

}
