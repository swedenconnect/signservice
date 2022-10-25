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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.SignatureException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.signature.AdESType;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.impl.DefaultRequestedSignatureTask;
import se.swedenconnect.signservice.signature.signer.TestAlgorithms;
import se.swedenconnect.signservice.signature.signer.TestCredentials;
import se.swedenconnect.signservice.signature.tbsdata.TBSProcessingData;
import se.swedenconnect.signservice.signature.testutils.TestData;
import se.swedenconnect.signservice.signature.testutils.TestUtils;

/**
 * PDF To Be Signed data processor tests
 */
@Slf4j
class PDFTBSDataProcessorTest {

  static PkiCredential testECCredential;
  static PkiCredential testRSACredential;
  static String tbsDataPdfBesSigTime;
  static String tbsDataPdfNoMessageDigest;
  static String tbsDataPdfNoContentType;
  static String tbsDataPdfNoAlgoProt;
  static PDFTBSDataProcessor tdp;
  static PDFTBSDataProcessor tdpIssuerSerial;
  static PDFTBSDataProcessor tdpStrict;
  static PDFTBSDataProcessor tdpPrules;

  @BeforeAll
  static void setUp() throws Exception {
    testECCredential = new BasicCredential(TestCredentials.ecCertificate, TestCredentials.privateECKey);
    testRSACredential = new BasicCredential(TestCredentials.rsaCertificate, TestCredentials.privateRSAKey);
    List<Attribute> attributes = PDFTBSDataProcessor.parseSignedAttributeBytes(Base64.decode(TestData.tbsDataPdfBes01));
    attributes.add(PDFTBSDataProcessor.getSigningTimeAttribute(null));
    tbsDataPdfBesSigTime = Base64.toBase64String(PDFTBSDataProcessor.consolidateTBSData(attributes));
    List<Attribute> noMsgDigestAttrList = attributes.stream()
      .filter(attribute -> !CMSAttributes.messageDigest.equals(attribute.getAttrType()))
      .collect(Collectors.toList());
    tbsDataPdfNoMessageDigest = Base64.toBase64String(PDFTBSDataProcessor.consolidateTBSData(noMsgDigestAttrList));
    List<Attribute> noContentTypeAttrList = attributes.stream()
      .filter(attribute -> !CMSAttributes.contentType.equals(attribute.getAttrType()))
      .collect(Collectors.toList());
    tbsDataPdfNoContentType = Base64.toBase64String(PDFTBSDataProcessor.consolidateTBSData(noContentTypeAttrList));

    List<Attribute> attributes2 = PDFTBSDataProcessor.parseSignedAttributeBytes(Base64.decode(TestData.tbsDataPdf01));
    List<Attribute> noCMSAlgoProtAttrList = attributes2.stream()
      .filter(attribute -> !CMSAttributes.cmsAlgorithmProtect.equals(attribute.getAttrType()))
      .filter(attribute -> !CMSAttributes.signingTime.equals(attribute.getAttrType()))
      .collect(Collectors.toList());
    tbsDataPdfNoAlgoProt = Base64.toBase64String(PDFTBSDataProcessor.consolidateTBSData(noCMSAlgoProtAttrList));

    tdp = new PDFTBSDataProcessor();
    tdpIssuerSerial = new PDFTBSDataProcessor();
    tdpIssuerSerial.setIncludeIssuerSerial(true);
    tdpStrict = new PDFTBSDataProcessor();
    tdpStrict.setStrictProcessing(true);
    tdpPrules = new PDFTBSDataProcessor(List.of("http://example.com/rule1", "http://example.com/rule2"));
  }

  @Test
  void getTBSData() throws Exception {

    testCasePddTbsDataProcessor("PAdES - ECDSA - ECDSA-SHA256", tdpStrict,
      getRequestedSignatureTask(
        TestData.tbsDataPdfBes01, SignatureType.PDF, AdESType.BES, null),
      testECCredential,
      TestAlgorithms.getEcdsaSha256(),
      TestData.resultTbsDataPdfBes01, null
    );

    testCasePddTbsDataProcessor("PAdES - ECDSA - ECDSA-SHA1", tdpStrict,
      getRequestedSignatureTask(
        TestData.tbsDataPdfBes01, SignatureType.PDF, AdESType.BES, null),
      testECCredential,
      TestAlgorithms.getEcdsaSha1(),
      TestData.resultTbsDataPdfBesSha1, null
    );

    testCasePddTbsDataProcessor("PAdES - ECDSA - ECDSA-SHA256 - Issuer Serial", tdpIssuerSerial,
      getRequestedSignatureTask(
        TestData.tbsDataPdfBes01, SignatureType.PDF, AdESType.BES, null),
      testECCredential,
      TestAlgorithms.getEcdsaSha256(),
      TestData.resultTbsDataPdfBesIssuerSerial, null
    );

    testCasePddTbsDataProcessor("Null requested processing rule", tdpPrules,
      getRequestedSignatureTask(
        TestData.tbsDataPdfBes01, SignatureType.PDF, AdESType.BES, null),
      testECCredential,
      TestAlgorithms.getEcdsaSha256(),
      null, null
    );

    testCasePddTbsDataProcessor("Specific requested processing rule", tdpPrules,
      getRequestedSignatureTask(
        TestData.tbsDataPdfBes01, SignatureType.PDF, AdESType.BES, "http://example.com/rule1"),
      testECCredential,
      TestAlgorithms.getEcdsaSha256(),
      null, null
    );

    testCasePddTbsDataProcessor("Specific requested processing rule", tdpPrules,
      getRequestedSignatureTask(
        TestData.tbsDataPdfBes01, SignatureType.PDF, AdESType.BES, "http://example.com/rule3"),
      testECCredential,
      TestAlgorithms.getEcdsaSha256(),
      null, SignatureException.class
    );

    testCasePddTbsDataProcessor("Specific requested processing rule - no rules", tdp,
      getRequestedSignatureTask(
        TestData.tbsDataPdfBes01, SignatureType.PDF, AdESType.BES, "http://example.com/rule3"),
      testECCredential,
      TestAlgorithms.getEcdsaSha256(),
      null, SignatureException.class
    );

    testCasePddTbsDataProcessor("Relaxed processing", tdp,
      getRequestedSignatureTask(
        tbsDataPdfBesSigTime, SignatureType.PDF, AdESType.BES, null),
      testECCredential,
      TestAlgorithms.getEcdsaSha256(),
      TestData.resultTbsDataPdfBes01, null
    );

    testCasePddTbsDataProcessor("Strict processing", tdpStrict,
      getRequestedSignatureTask(
        tbsDataPdfBesSigTime, SignatureType.PDF, AdESType.BES, null),
      testECCredential,
      TestAlgorithms.getEcdsaSha256(),
      TestData.resultTbsDataPdfBes01, SignatureException.class
    );

    testCasePddTbsDataProcessor("Wrong signature type", tdp,
      getRequestedSignatureTask(
        tbsDataPdfBesSigTime, SignatureType.XML, AdESType.BES, null),
      testECCredential,
      TestAlgorithms.getEcdsaSha256(),
      null, SignatureException.class
    );

    testCasePddTbsDataProcessor("No message digest", tdp,
      getRequestedSignatureTask(
        tbsDataPdfNoMessageDigest, SignatureType.PDF, AdESType.BES, null),
      testECCredential,
      TestAlgorithms.getEcdsaSha256(),
      null, SignatureException.class
    );

    testCasePddTbsDataProcessor("No contentType", tdp,
      getRequestedSignatureTask(
        tbsDataPdfNoContentType, SignatureType.PDF, AdESType.BES, null),
      testECCredential,
      TestAlgorithms.getEcdsaSha256(),
      null, SignatureException.class
    );

    testCasePddTbsDataProcessor("No PAdES signature with signing time and strict", tdpStrict,
      getRequestedSignatureTask(
        TestData.fixCMSSigTime(TestData.tbsDataPdf01), SignatureType.PDF, null, null),
      testECCredential,
      TestAlgorithms.getEcdsaSha256(),
      null, null
    );

    testCasePddTbsDataProcessor("No PAdES signature and no CMS Algo protection", tdpStrict,
      getRequestedSignatureTask(
        tbsDataPdfNoAlgoProt, SignatureType.PDF, null, null),
      testECCredential,
      TestAlgorithms.getEcdsaSha256(),
      TestData.resultNoPadesNoTime, null
    );

    testCasePddTbsDataProcessor("No PAdES signature and no CMS Algo protection", tdpStrict,
      getRequestedSignatureTask(
        tbsDataPdfNoAlgoProt, SignatureType.PDF, null, null),
      testECCredential,
      TestAlgorithms.getEcdsaSha256(),
      TestData.resultNoPadesNoTime, null
    );
  }

  @Test
  public void testOldSigningTime() throws Exception {
    Instant signingTime = Instant.now().minusSeconds(250);
    testCasePddTbsDataProcessor("Testing PDF signing with too old signing time", tdpStrict,
      getRequestedSignatureTask(
        TestData.fixCMSSigTime(TestData.tbsDataPdf01, signingTime), SignatureType.PDF, null, null),
      testECCredential,
      TestAlgorithms.getEcdsaSha256(),
      null, SignatureException.class
    );
  }

  @Test
  public void testFutureSigningTime() throws Exception {
    Instant signingTime = Instant.now().plusSeconds(50);
    testCasePddTbsDataProcessor("Testing PDF signing with future signing time", tdpStrict,
      getRequestedSignatureTask(
        TestData.fixCMSSigTime(TestData.tbsDataPdf01, signingTime), SignatureType.PDF, null, null),
      testECCredential,
      TestAlgorithms.getEcdsaSha256(),
      null, SignatureException.class
    );
  }

  @Test
  public void testBadSigningTime() throws Exception {

    testCasePddTbsDataProcessor("Testing PDF signing with bad signing time", tdpStrict,
      getRequestedSignatureTask(
        TestData.fixCMSSigTime(TestData.tbsDataPdf01, Instant.now(), true), SignatureType.PDF, null, null),
      testECCredential,
      TestAlgorithms.getEcdsaSha256(),
      null, SignatureException.class
    );
  }

  @Test
  public void generalStaticFunctionTests() throws Exception {
    Exception e = assertThrows(IOException.class, () -> PDFTBSDataProcessor.parseSignedAttributeBytes(new byte[] {}));
    log.info("Caught exception parsing illegal tbs data {}", e.toString());

    List<Attribute> attributes = PDFTBSDataProcessor.parseSignedAttributeBytes(Base64.decode(TestData.tbsDataPdf01));
    Date cmsSigningTime = PDFTBSDataProcessor.getCmsSigningTime(attributes);
    log.info("Found signing time: {} - {} ms since epoch", cmsSigningTime, cmsSigningTime.getTime());
    assertEquals(1654724214000L, cmsSigningTime.getTime());

  }

  private void testCasePddTbsDataProcessor(String message, PDFTBSDataProcessor pdftbsDataProcessor,
    RequestedSignatureTask signatureTask, PkiCredential credential, SignatureAlgorithm signatureAlgorithm,
    String expectedResult, Class<? extends Exception> exceptionClass)
    throws Exception {

    log.info("PDF TBS test data processor test: " + message);

    // Test exception case
    if (exceptionClass != null) {
      Exception exception = assertThrows(exceptionClass,
        () -> pdftbsDataProcessor.processSignTaskData(signatureTask, credential.getCertificate(), signatureAlgorithm));
      assertTrue(exceptionClass.isAssignableFrom(exception.getClass()));
      log.info("Caught exception: {}", exception.toString());
      return;
    }

    // Test positive result
    log.info("Processing input data:\n{}", TestUtils.base64Print(signatureTask.getTbsData(), 80));
    TBSProcessingData tbsData = pdftbsDataProcessor.processSignTaskData(signatureTask, credential.getCertificate(),
      signatureAlgorithm);

    // Remove later
    log.debug(Base64.toBase64String(tbsData.getTBSBytes()));

    log.info("Result tbs data:\n{}", TestUtils.base64Print(tbsData.getTBSBytes(), 80));
    if (expectedResult != null) {
      assertArrayEquals(Base64.decode(expectedResult), tbsData.getTBSBytes());
    }
    assertEquals(null, tbsData.getAdESObject());
    assertEquals(signatureTask.getProcessingRulesUri(), tbsData.getProcessingRules());
  }

  private RequestedSignatureTask getRequestedSignatureTask(String tbsDataB64, SignatureType signatureType,
    AdESType adESType, String processingRules) {
    DefaultRequestedSignatureTask signatureTask = new DefaultRequestedSignatureTask();
    signatureTask.setTaskId("id01");
    signatureTask.setSignatureType(signatureType);
    signatureTask.setTbsData(Base64.decode(tbsDataB64));
    signatureTask.setAdESType(adESType);
    signatureTask.setProcessingRulesUri(processingRules);
    return signatureTask;
  }
}