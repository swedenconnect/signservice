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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.binding.xmldsig.ObjectType;
import org.apache.xml.security.binding.xmldsig.ReferenceType;
import org.apache.xml.security.binding.xmldsig.SignedInfoType;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import se.idsec.signservice.xml.DOMUtils;
import se.idsec.signservice.xml.JAXBMarshaller;
import se.idsec.signservice.xml.JAXBUnmarshaller;
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
import se.swedenconnect.signservice.signature.tbsdata.TBSProcessingData;
import se.swedenconnect.signservice.signature.testutils.TestUtils;

import java.security.MessageDigest;
import java.security.SignatureException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
class XMLTBSDataProcessorTest {

  static PkiCredential testECCredential;
  static PkiCredential testRSACredential;

  static String tbsDataAdes01 =
    "PGRzOlNpZ25lZEluZm8geG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPgo8ZHM6Q2Fub2"
      + "5pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyI+PC9kczpDYW5vbml"
      + "jYWxpemF0aW9uTWV0aG9kPgo8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2ln"
      + "LW1vcmUjcnNhLXNoYTI1NiI+PC9kczpTaWduYXR1cmVNZXRob2Q+CjxkczpSZWZlcmVuY2UgVVJJPSIiPgo8ZHM6VHJhbnNmb3Jtcz4KPGRzO"
      + "lRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIj48L2RzOl"
      + "RyYW5zZm9ybT4KPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyI+PC9kczp"
      + "UcmFuc2Zvcm0+CjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy9UUi8xOTk5L1JFQy14cGF0aC0xOTk5MTExNiI+"
      + "CjxkczpYUGF0aD5ub3QoYW5jZXN0b3Itb3Itc2VsZjo6ZHM6U2lnbmF0dXJlKTwvZHM6WFBhdGg+CjwvZHM6VHJhbnNmb3JtPgo8L2RzOlRyY"
      + "W5zZm9ybXM+CjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiPjwvZH"
      + "M6RGlnZXN0TWV0aG9kPgo8ZHM6RGlnZXN0VmFsdWU+SFJQMGZjMFNXNE9Wb1E0MDdpSnFyYmdXM0Rheks0Qkt0TVZoRUhIR3M3UT08L2RzOkR"
      + "pZ2VzdFZhbHVlPgo8L2RzOlJlZmVyZW5jZT4KPGRzOlJlZmVyZW5jZSBUeXBlPSJodHRwOi8vdXJpLmV0c2kub3JnLzAxOTAzI1NpZ25lZFBy"
      + "b3BlcnRpZXMiIFVSST0iI3hhZGVzLWlkLWI2NWM0MTI5ODI1NWEzODcxNmI2YjczNGQ4OWNkYWJiIj4KPGRzOlRyYW5zZm9ybXM+CjxkczpUc"
      + "mFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiPjwvZHM6VHJhbnNmb3JtPgo8L2RzOl"
      + "RyYW5zZm9ybXM+CjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiPjw"
      + "vZHM6RGlnZXN0TWV0aG9kPgo8ZHM6RGlnZXN0VmFsdWU+MmZXL3FyazBJc3lIa05vRXdXZENEaGpYUkpHSjQxdVRyV29hTksxSVF1dz08L2Rz"
      + "OkRpZ2VzdFZhbHVlPgo8L2RzOlJlZmVyZW5jZT4KPC9kczpTaWduZWRJbmZvPg==";

  static String reqAdesObject01 =
    "PGRzOk9iamVjdCB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PHhhZGVzOlF1YW"
      + "xpZnlpbmdQcm9wZXJ0aWVzIHhtbG5zOnhhZGVzPSJodHRwOi8vdXJpLmV0c2kub3JnLzAxOTAzL3YxLjMuMiMiIFRhcmdldD0iI2lkLTg3ZGI"
      + "wZGZjOGU1OGMyOTQ3MWRhOTM0YzE5NDkxMGIzIj48eGFkZXM6U2lnbmVkUHJvcGVydGllcyBJZD0ieGFkZXMtaWQtYjY1YzQxMjk4MjU1YTM4"
      + "NzE2YjZiNzM0ZDg5Y2RhYmIiPjx4YWRlczpTaWduZWRTaWduYXR1cmVQcm9wZXJ0aWVzPjx4YWRlczpTaWduaW5nVGltZT4yMDIyLTA2LTA5V"
      + "DEzOjU1OjQ3LjA5MCswMjowMDwveGFkZXM6U2lnbmluZ1RpbWU+PHhhZGVzOlNpZ25pbmdDZXJ0aWZpY2F0ZVYyPjx4YWRlczpDZXJ0Pjx4YW"
      + "RlczpDZXJ0RGlnZXN0PjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTY"
      + "iPjwvZHM6RGlnZXN0TWV0aG9kPjxkczpEaWdlc3RWYWx1ZT5sYUJXVTlvaTZjN2dQNzIrZUl3L3JzM3Z2bW1SUzFYTWRWVytmZDhFNWdNPTwv"
      + "ZHM6RGlnZXN0VmFsdWU+PC94YWRlczpDZXJ0RGlnZXN0Pjx4YWRlczpJc3N1ZXJTZXJpYWxWMj5NQ0l3R0tRV01CUXhFakFRQmdOVkJBTU1DW"
      + "EJ5WlhOcFoyNWxjZ0lHQVlGSVVidlM8L3hhZGVzOklzc3VlclNlcmlhbFYyPjwveGFkZXM6Q2VydD48L3hhZGVzOlNpZ25pbmdDZXJ0aWZpY2"
      + "F0ZVYyPjwveGFkZXM6U2lnbmVkU2lnbmF0dXJlUHJvcGVydGllcz48L3hhZGVzOlNpZ25lZFByb3BlcnRpZXM+PC94YWRlczpRdWFsaWZ5aW5"
      + "nUHJvcGVydGllcz48L2RzOk9iamVjdD4=";

  static String tbsDataNoAdes = "PGRzOlNpZ25lZEluZm8geG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkc"
    + "zpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIj48L2RzOkNh"
    + "bm9uaWNhbGl6YXRpb25NZXRob2Q+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHN"
    + "pZy1tb3JlI2VjZHNhLXNoYTI1NiI+PC9kczpTaWduYXR1cmVNZXRob2Q+PGRzOlJlZmVyZW5jZSBVUkk9IiI+PGRzOlRyYW5zZm9ybXM+PGRzOl"
    + "RyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIj48L2RzOlRyY"
    + "W5zZm9ybT48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIj48L2RzOlRyYW5z"
    + "Zm9ybT48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvVFIvMTk5OS9SRUMteHBhdGgtMTk5OTExMTYiPgo8ZHM6WFB"
    + "hdGg+bm90KGFuY2VzdG9yLW9yLXNlbGY6OipbbG9jYWwtbmFtZSgpPSdTaWduYXR1cmUnIGFuZCBuYW1lc3BhY2UtdXJpKCk9J2h0dHA6Ly93d3"
    + "cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMnXSk8L2RzOlhQYXRoPgo8L2RzOlRyYW5zZm9ybT48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ld"
    + "GhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiI+PC9kczpEaWdlc3RNZXRob2Q+PGRzOkRpZ2Vz"
    + "dFZhbHVlPjkwN3dxZ0VBOFVSZEx2ZE9JeWloQTQxdlJ3UlNRYWZNd3ovUk42N2xZQ0k9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT4"
    + "8L2RzOlNpZ25lZEluZm8+";

  static String tbsDataNoRef = getNoRefSignedIfo();

  static String reqAdesObjectWithV1CertRef = getV1CertRefAdesObject();

  static String signatureId01 = "id-87db0dfc8e58c29471da934c194910b3";

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
      .tbsData(tbsDataAdes01)
      .requestAdesObject(reqAdesObject01)
      .signatureId(signatureId01)
      .credential(testECCredential)
      .signatureAlgorithm(TestAlgorithms.getEcdsaSha256())
      .build());

    testCase(TestInput.builder()
      .description("Default request with no input AdES object")
      .sigType(SignatureType.XML).adESType(AdESType.BES).processingRules(null)
      .tbsData(tbsDataAdes01)
      .signatureId(signatureId01)
      .credential(testECCredential)
      .signatureAlgorithm(TestAlgorithms.getEcdsaSha256())
      .build());

    testCase(TestInput.builder()
      .description("Include issuer serial")
      .sigType(SignatureType.XML).adESType(AdESType.BES).processingRules(null)
      .tbsData(tbsDataAdes01)
      .signatureId(signatureId01)
      .credential(testECCredential)
      .signatureAlgorithm(TestAlgorithms.getEcdsaSha256())
      .tbsDataProcessor(issuerSerialTbsDataprocessor)
      .includeIssuerSerial(true)
      .build());

    testCase(TestInput.builder()
      .description("No AdES Signature")
      .sigType(SignatureType.XML).adESType(null).processingRules(null)
      .tbsData(tbsDataNoAdes)
      .credential(testECCredential)
      .signatureAlgorithm(TestAlgorithms.getEcdsaSha256())
      .build());

    testCase(TestInput.builder()
      .description("Remove V1 Signing Certificate ref")
      .sigType(SignatureType.XML).adESType(AdESType.BES).processingRules(null)
      .tbsData(tbsDataAdes01)
      .requestAdesObject(reqAdesObjectWithV1CertRef)
      .signatureId(signatureId01)
      .credential(testECCredential)
      .signatureAlgorithm(TestAlgorithms.getEcdsaSha256())
      .build());

    testCase(TestInput.builder()
      .description("Request with no references in signed data")
      .sigType(SignatureType.XML).adESType(AdESType.BES)
      .tbsData(tbsDataNoRef)
      .credential(testECCredential)
      .signatureId(signatureId01)
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
      .tbsData(tbsDataAdes01)
      .signatureAlgorithm(TestAlgorithms.getEcdsaSha256())
      .exception(NullPointerException.class)
      .build());

    testCase(TestInput.builder()
      .description("Null Signature Algorithm")
      .sigType(SignatureType.XML).adESType(AdESType.BES)
      .tbsData(tbsDataAdes01)
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
      .tbsData(tbsDataAdes01)
      .credential(testECCredential)
      .signatureAlgorithm(TestAlgorithms.getEcdsaSha256())
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
      Exception exception = assertThrows(input.exception, () -> tbsDP.getTBSData(
        requestedSignatureTask, input.credential, input.signatureAlgorithm
      ));
      log.info("Caught exception: {}", exception.toString());
      return;
    }

    // Non exception test
    TBSProcessingData tbsData = tbsDP.getTBSData(requestedSignatureTask, input.credential, input.signatureAlgorithm);
    log.info("Result tbs data:\n{}", TestUtils.base64Print(tbsData.getTBSBytes()));
    if (tbsData.getAdESObject() != null) {
      log.info("Result AdES object:\n{}", TestUtils.base64Print(tbsData.getAdESObject().getObjectBytes()));
      log.info("Result AdES object signature ID: {}", tbsData.getAdESObject().getSignatureId());
    }
    else {
      log.info("No result AdES object");
    }

    Document inpTbsDocument = DOMUtils.bytesToDocument(Base64.decode(input.tbsData));
    SignedInfoType inpSignedInfo = JAXBUnmarshaller.unmarshall(inpTbsDocument, SignedInfoType.class);

    Document tbsDocument = DOMUtils.bytesToDocument(tbsData.getTBSBytes());
    SignedInfoType signedInfo = JAXBUnmarshaller.unmarshall(tbsDocument, SignedInfoType.class);

    assertEquals(inpSignedInfo.getCanonicalizationMethod().getAlgorithm(),
      signedInfo.getCanonicalizationMethod().getAlgorithm());
    log.info("Input and output tbs data has matching canonicalization algorithm");
    assertEquals(inpSignedInfo.getSignatureMethod().getAlgorithm(), signedInfo.getSignatureMethod().getAlgorithm());
    log.info("Input and output tbs data has matching signature algorithm");

    if (input.adESType == null) {
      // This is a non AdES test
      assertNull(tbsData.getAdESObject());
      assertArrayEquals(Base64.decode(input.tbsData), tbsData.getTBSBytes());
      log.info("Non AdES request. input data and TBS data match");
      return;
    }

    Document adesObjectDocument = DOMUtils.bytesToDocument(tbsData.getAdESObject().getObjectBytes());
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

    byte[] sigPropDigest = md.digest(signedPropertyBytes);

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
    Document adesObjectDocument = DOMUtils.bytesToDocument(Base64.decode(reqAdesObject01));
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
    Document inpTbsDocument = DOMUtils.bytesToDocument(Base64.decode(tbsDataNoAdes));
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