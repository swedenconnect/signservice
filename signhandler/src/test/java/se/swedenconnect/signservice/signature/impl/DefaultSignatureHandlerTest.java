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
package se.swedenconnect.signservice.signature.impl;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import se.idsec.signservice.integration.core.Extension;
import se.idsec.signservice.integration.document.CompiledSignedDocument;
import se.idsec.signservice.integration.document.DocumentType;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.pdf.PAdESData;
import se.idsec.signservice.integration.document.pdf.PDFExtensionParams;
import se.idsec.signservice.integration.document.pdf.PdfSignedDocumentProcessor;
import se.idsec.signservice.integration.document.xml.XadesQualifyingProperties;
import se.idsec.signservice.integration.document.xml.XmlSignedDocumentProcessor;
import se.idsec.signservice.integration.dss.SignRequestWrapper;
import se.idsec.signservice.security.sign.AdesProfileType;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.signservice.security.sign.pdf.PDFSignatureValidator;
import se.idsec.signservice.security.sign.pdf.PDFSignerParameters;
import se.idsec.signservice.security.sign.pdf.PDFSignerResult;
import se.idsec.signservice.security.sign.pdf.impl.BasicPDFSignatureValidator;
import se.idsec.signservice.security.sign.pdf.impl.DefaultPDFSigner;
import se.idsec.signservice.security.sign.xml.XMLSigner;
import se.idsec.signservice.security.sign.xml.XMLSignerResult;
import se.idsec.signservice.security.sign.xml.impl.DefaultXMLSignatureValidator;
import se.idsec.signservice.security.sign.xml.impl.DefaultXMLSigner;
import se.idsec.signservice.xml.DOMUtils;
import se.swedenconnect.schemas.csig.dssext_1_1.AdESObject;
import se.swedenconnect.schemas.csig.dssext_1_1.Base64Signature;
import se.swedenconnect.security.algorithms.Algorithm;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.msg.SignatureRequirements;
import se.swedenconnect.signservice.session.SignServiceContext;
import se.swedenconnect.signservice.signature.*;
import se.swedenconnect.signservice.signature.signer.TestAlgorithms;
import se.swedenconnect.signservice.signature.signer.TestCredentials;
import se.swedenconnect.signservice.signature.signer.impl.DefaultSignServiceSignerProvider;
import se.swedenconnect.signservice.signature.tbsdata.impl.DefaultTBSDataProcessorProvider;
import se.swedenconnect.signservice.signature.tbsdata.impl.PDFTBSDataProcessor;
import se.swedenconnect.signservice.signature.tbsdata.impl.XMLTBSDataProcessor;
import se.swedenconnect.signservice.signature.testutils.TestData;
import se.swedenconnect.signservice.signature.testutils.TestUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test cases for DefaultSignatureHandler including integration tests for XML and PDF document signing and validation
 */
@Slf4j
public class DefaultSignatureHandlerTest {

  private static final se.swedenconnect.schemas.csig.dssext_1_1.ObjectFactory dssExtFactory =
    new se.swedenconnect.schemas.csig.dssext_1_1.ObjectFactory();

  static AlgorithmRegistry algorithmRegistry;
  static PkiCredential testECCredential;
  static PkiCredential testRSACredential;
  static PkiCredential testECPresignCredential;
  static PkiCredential testRSAPresignCredential;
  static byte[] testPdfDocBytes;

  @BeforeAll
  static void setup() throws IOException {
    org.apache.xml.security.Init.init();
    algorithmRegistry = AlgorithmRegistrySingleton.getInstance();
    testECCredential = new BasicCredential(TestCredentials.ecCertificate, TestCredentials.privateECKey);
    testRSACredential = new BasicCredential(TestCredentials.rsaCertificate, TestCredentials.privateRSAKey);
    testECPresignCredential = new BasicCredential(TestCredentials.ecPresignCertificate,
      TestCredentials.privateECPresignKey);
    testRSAPresignCredential = new BasicCredential(TestCredentials.rsaPresignCertificate,
      TestCredentials.privateRSAPresignKey);

    testPdfDocBytes = IOUtils.toByteArray(
      Objects.requireNonNull(DefaultSignatureHandlerTest.class.getResourceAsStream("/testdoc.pdf")));
  }


  @Test void pdfIntegrationTest() throws Exception {
    pdfIntegrationTestInstance(TestAlgorithms.ecdsaSha256, true);
    pdfIntegrationTestInstance(TestAlgorithms.ecdsaSha384, true);
    pdfIntegrationTestInstance(TestAlgorithms.ecdsaSha512, true);
    pdfIntegrationTestInstance(TestAlgorithms.ecdsaSha256, false);
    pdfIntegrationTestInstance(TestAlgorithms.rsaSha256, true);
    pdfIntegrationTestInstance(TestAlgorithms.rsaPssSha256, true);
    pdfIntegrationTestInstance(TestAlgorithms.rsaPssSha512, true);
    pdfIntegrationTestInstance(TestAlgorithms.rsaPssSha512, false);
  }

  void pdfIntegrationTestInstance(SignatureAlgorithm signatureAlgorithm, boolean ades) throws Exception {
    log.info("Integration test for XML signature - Algorithm: {}, AdES={}", signatureAlgorithm.getJcaName(), ades);

    XMLTBSDataProcessor xmltbsDataProcessor = new XMLTBSDataProcessor();
    PDFTBSDataProcessor pdftbsDataProcessor = new PDFTBSDataProcessor();
    pdftbsDataProcessor.setIncludeIssuerSerial(true);
    pdftbsDataProcessor.setStrictProcessing(true);
    DefaultTBSDataProcessorProvider tbsDataProcessorProvider = new DefaultTBSDataProcessorProvider(xmltbsDataProcessor, pdftbsDataProcessor);
    DefaultSignatureHandler signatureHandler = new DefaultSignatureHandler(algorithmRegistry,
      new DefaultSignServiceSignerProvider(algorithmRegistry), tbsDataProcessorProvider);


    String signatureAlgorithmUri = signatureAlgorithm.getUri();
    PkiCredential preSignCredential = signatureAlgorithm.getKeyType().equals("EC")
      ? testECPresignCredential : testRSAPresignCredential;
    PkiCredential signCredential = signatureAlgorithm.getKeyType().equals("EC")
      ? testECCredential : testRSACredential;

    // Pre-sign document
    final DefaultPDFSigner signer = new DefaultPDFSigner(preSignCredential, signatureAlgorithmUri);
    signer.setIncludeCertificateChain(false);
    final PDFSignerParameters signerParameters = PDFSignerParameters.builder()
      .padesType(ades ? AdesProfileType.BES : null)
      .build();
    final PDFSignerResult pdfSignerResult = signer.sign(testPdfDocBytes, signerParameters);
    log.info("Pre-signed signed attributes:\n{}", TestUtils.base64Print(pdfSignerResult.getSignedAttributes()));

    // Perform signature service signing
    SignRequestMessage signRequest = getSignRequest(signatureAlgorithm, List.of(
      getRequestedSignatureTask(Base64.toBase64String(pdfSignerResult.getSignedAttributes()), SignatureType.PDF,
        ades ? AdESType.BES : null,null,null,null)));
    CompletedSignatureTask completedSignatureTask = signatureHandler.sign(signRequest.getSignatureTasks().get(0),
      signCredential, signRequest,null);
    log.info("Sign service TBS signed attributes:\n{}", TestUtils.base64Print(completedSignatureTask.getTbsData()));

    // Back to integration service prepare the result for signed document assembly
    PdfSignedDocumentProcessor documentProcessor = new PdfSignedDocumentProcessor();
    Map<String, String> extMap = new HashMap<>();
    extMap.put(PDFExtensionParams.signTimeAndId.name(), String.valueOf(pdfSignerResult.getSigningTime()));
    extMap.put(PDFExtensionParams.cmsSignedData.name(), Base64.toBase64String(pdfSignerResult.getSignedData()));
    TbsDocument tbsDocument = TbsDocument.builder()
      .adesRequirement(TbsDocument.EtsiAdesRequirement.builder().adesFormat(ades ? TbsDocument.AdesType.BES : null).build())
      .content(Base64.toBase64String(testPdfDocBytes))
      .mimeType(DocumentType.PDF.getMimeType())
      .extension(new Extension(extMap))
      .build();
    SignRequestWrapper signRequestWrapper = mock(SignRequestWrapper.class);
    when(signRequestWrapper.getRequestID()).thenReturn("id-019283901283");
    se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData signTaskData = dssExtFactory.createSignTaskData();
    if (completedSignatureTask.getAdESObject() != null) {
      AdESObject adESObject = dssExtFactory.createAdESObject();
      adESObject.setSignatureId(completedSignatureTask.getAdESObject().getSignatureId());
      adESObject.setAdESObjectBytes(completedSignatureTask.getAdESObject().getObjectBytes());
      signTaskData.setAdESObject(adESObject);
      signTaskData.setAdESType(completedSignatureTask.getAdESType().name());
    }
    signTaskData.setSignTaskId("id01");
    signTaskData.setToBeSignedBytes(completedSignatureTask.getTbsData());
    signTaskData.setSigType(completedSignatureTask.getSignatureType().getType());
    Base64Signature base64Signature = dssExtFactory.createBase64Signature();
    base64Signature.setType(signatureAlgorithmUri);
    base64Signature.setValue(completedSignatureTask.getSignature());
    signTaskData.setBase64Signature(base64Signature);
    // Assemble signed document

    CompiledSignedDocument<byte[], PAdESData> pAdESDataCompiledSignedDocument = documentProcessor.buildSignedDocument(
      tbsDocument, signTaskData, List.of(signCredential.getCertificate()), signRequestWrapper, null);

    // Validate the signed document
    final PDFSignatureValidator validator = new BasicPDFSignatureValidator();
    FileUtils.writeByteArrayToFile(new File(System.getProperty("user.dir") , "target/signed.pdf"), pAdESDataCompiledSignedDocument.getDocument());
    List<SignatureValidationResult> validationResults = validator.validate(pAdESDataCompiledSignedDocument.getDocument());
    assertEquals(1, validationResults.size());
    assertEquals(SignatureValidationResult.Status.SUCCESS, validationResults.get(0).getStatus());
    assertEquals(signCredential.getCertificate(), validationResults.get(0).getSignerCertificate());
    log.info("Successful validation of signed PDF document");
  }

  @Test void xmlIntegrationTest() throws Exception {
    xmlIntegrationTestInstance(TestAlgorithms.getEcdsaSha256(), true);
    xmlIntegrationTestInstance(TestAlgorithms.getEcdsaSha384(), true);
    xmlIntegrationTestInstance(TestAlgorithms.getEcdsaSha512(), true);
    xmlIntegrationTestInstance(TestAlgorithms.getEcdsaSha256(), false);
    xmlIntegrationTestInstance(TestAlgorithms.getRsaSha256(), true);
    xmlIntegrationTestInstance(TestAlgorithms.getRsaPssSha256(), true);
    xmlIntegrationTestInstance(TestAlgorithms.getRsaPssSha512(), true);
    xmlIntegrationTestInstance(TestAlgorithms.getRsaPssSha512(), false);
  }


  void xmlIntegrationTestInstance(SignatureAlgorithm signatureAlgorithm, boolean ades) throws Exception {
    log.info("Integration test for XML signature - Algorithm: {}, AdES={}", signatureAlgorithm.getJcaName(), ades);
    DefaultSignatureHandler signatureHandler = new DefaultSignatureHandler(algorithmRegistry,
      new DefaultSignServiceSignerProvider(algorithmRegistry), new DefaultTBSDataProcessorProvider());

    // Document to sign
    Document testDoc = DOMUtils.bytesToDocument(("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      + "<test><parameter type=\"string\">Value</parameter></test>").getBytes(StandardCharsets.UTF_8));
    String tbsDocB64 = DOMUtils.nodeToBase64(testDoc);
    PkiCredential preSignCredential = signatureAlgorithm.getKeyType().equals("EC")
      ? testECPresignCredential : testRSAPresignCredential;
    PkiCredential signCredential = signatureAlgorithm.getKeyType().equals("EC")
      ? testECCredential : testRSACredential;

    // Pre-sign document
    String signatureAlgorithmUri = signatureAlgorithm.getUri();
    final XMLSigner xmlPresigner = DefaultXMLSigner.builder(preSignCredential)
      .signatureAlgorithm(signatureAlgorithmUri)
      .includeSignatureId(true)
      .build();
    final XMLSignerResult preSignResult = xmlPresigner.sign(testDoc);
    log.info("Pre Signed Document:\n{}", DOMUtils.prettyPrint(preSignResult.getSignedDocument()).replaceAll("\\n[ ]+\\n", "\n"));

    // Perform signature service signing
    SignRequestMessage signRequest = getSignRequest(signatureAlgorithm, List.of(
      getRequestedSignatureTask(Base64.toBase64String(preSignResult.getCanonicalizedSignedInfo()), SignatureType.XML,
        ades ? AdESType.BES : null,
        preSignResult.getSignatureElement().getAttribute("Id"),
        null, null)
    ));
    CompletedSignatureTask completedSignatureTask = signatureHandler.sign(signRequest.getSignatureTasks().get(0),
      signCredential,
      signRequest, null);

    // Back to integration service prepare the result for signed document assembly
    XmlSignedDocumentProcessor documentProcessor = new XmlSignedDocumentProcessor();
    TbsDocument tbsDocument = TbsDocument.builder()
      .adesRequirement(TbsDocument.EtsiAdesRequirement.builder().adesFormat(ades ? TbsDocument.AdesType.BES : null).build())
      .content(tbsDocB64)
      .mimeType(DocumentType.XML.getMimeType())
      .contentReference("")
      .build();
    SignRequestWrapper signRequestWrapper = mock(SignRequestWrapper.class);
    when(signRequestWrapper.getRequestID()).thenReturn("id-019283901283");
    se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData signTaskData = dssExtFactory.createSignTaskData();
    if (completedSignatureTask.getAdESObject() != null) {
      AdESObject adESObject = dssExtFactory.createAdESObject();
      adESObject.setSignatureId(completedSignatureTask.getAdESObject().getSignatureId());
      adESObject.setAdESObjectBytes(completedSignatureTask.getAdESObject().getObjectBytes());
      signTaskData.setAdESObject(adESObject);
      signTaskData.setAdESType(completedSignatureTask.getAdESType().name());
    }
    signTaskData.setSignTaskId("id01");
    signTaskData.setToBeSignedBytes(completedSignatureTask.getTbsData());
    signTaskData.setSigType(completedSignatureTask.getSignatureType().getType());
    Base64Signature base64Signature = dssExtFactory.createBase64Signature();
    base64Signature.setType(signatureAlgorithmUri);
    base64Signature.setValue(completedSignatureTask.getSignature());
    signTaskData.setBase64Signature(base64Signature);
    // Assemble signed document
    CompiledSignedDocument<Document, XadesQualifyingProperties> signedDocument = documentProcessor.buildSignedDocument(
      tbsDocument, signTaskData, List.of(signCredential.getCertificate()), signRequestWrapper, null);
    log.info("Signed Document:\n{}", DOMUtils.prettyPrint(signedDocument.getDocument()).replaceAll("\\n[ ]+\\n", "\n"));

    // Validate the signed document
    final DefaultXMLSignatureValidator validator = new DefaultXMLSignatureValidator(signCredential.getCertificate());
    List<SignatureValidationResult> validationResults = validator.validate(signedDocument.getDocument());
    assertEquals(1, validationResults.size());
    assertEquals(SignatureValidationResult.Status.SUCCESS, validationResults.get(0).getStatus());
    log.info("Successful validation of signed XML document");
  }

  @Test
  public void testName() {
    log.info("DefaultSignatureHandler tests");
    AlgorithmRegistrySingleton algorithmRegistry = AlgorithmRegistrySingleton.getInstance();
    DefaultSignatureHandler handler1 = new DefaultSignatureHandler(algorithmRegistry);
    handler1.setName("handler1Name");
    assertEquals("handler1Name", handler1.getName());

    DefaultSignatureHandler handler = new DefaultSignatureHandler(algorithmRegistry,
      new DefaultSignServiceSignerProvider(algorithmRegistry), new DefaultTBSDataProcessorProvider());

    Assertions.assertEquals(DefaultSignatureHandler.class.getSimpleName(), handler.getName());
  }

  @Test
  public void checkRequirementsTestInstance() throws Exception {
    DefaultSignatureHandler handler = new DefaultSignatureHandler(algorithmRegistry,
      new DefaultSignServiceSignerProvider(algorithmRegistry), new DefaultTBSDataProcessorProvider());

    Assertions.assertEquals(DefaultSignatureHandler.class.getSimpleName(), handler.getName());

    checkRequirementsTestInstance("Basic PDF requirements test with PDF and XML sign task", handler,
      getSignRequest(TestAlgorithms.getEcdsaSha256(), List.of(
        getRequestedSignatureTask(TestData.tbsDataPdfBes01, SignatureType.PDF, AdESType.BES, null, null, null),
        getRequestedSignatureTask(TestData.tbsDataXmlNoAdes, SignatureType.XML, null, null, null, null)
      )), null, null);

    checkRequirementsTestInstance("Single XML AdES check", handler,
      getSignRequest(TestAlgorithms.getRsaSha256(), List.of(
        getRequestedSignatureTask(TestData.tbsDataXmlAdes01, SignatureType.XML, AdESType.BES, TestData.signatureId01,
          TestData.tbsDataXmlAdes01, null)
      )), null, null);

    checkRequirementsTestInstance("Conflicting algorithms", handler,
      getSignRequest(TestAlgorithms.getEcdsaSha256(), List.of(
        getRequestedSignatureTask(TestData.tbsDataXmlAdes01, SignatureType.XML, AdESType.BES, TestData.signatureId01,
          TestData.tbsDataXmlAdes01, null)
      )), null, InvalidRequestException.class);

    checkRequirementsTestInstance("No algorithm", handler,
      getSignRequest(null, List.of(
        getRequestedSignatureTask(TestData.tbsDataXmlAdes01, SignatureType.XML, AdESType.BES, TestData.signatureId01,
          TestData.tbsDataXmlAdes01, null)
      )), null, InvalidRequestException.class);

    checkRequirementsTestInstance("No sign tasks", handler,
      getSignRequest(TestAlgorithms.getRsaSha256(), List.of(
      )), null, InvalidRequestException.class);

    checkRequirementsTestInstance("No signature Id in XML AdES request", handler,
      getSignRequest(TestAlgorithms.getRsaSha256(), List.of(
        getRequestedSignatureTask(TestData.tbsDataXmlAdes01, SignatureType.XML, AdESType.BES, null,
          TestData.tbsDataXmlAdes01, null)
      )), null, InvalidRequestException.class);

    checkRequirementsTestInstance("Illegal XML request data", handler,
      getSignRequest(TestAlgorithms.getRsaSha256(), List.of(
        getRequestedSignatureTask(TestData.tbsDataPdf01, SignatureType.XML, AdESType.BES, TestData.signatureId01, null,
          null)
      )), null, InvalidRequestException.class);

    checkRequirementsTestInstance("Illegal PDF request data", handler,
      getSignRequest(TestAlgorithms.getRsaSha256(), List.of(
        getRequestedSignatureTask(TestData.tbsDataXmlNoAdes, SignatureType.PDF, null, null, null, null)
      )), null, InvalidRequestException.class);

  }

  @Test
  void signTest() throws Exception {
    DefaultSignatureHandler handler = new DefaultSignatureHandler(algorithmRegistry,
      new DefaultSignServiceSignerProvider(algorithmRegistry), new DefaultTBSDataProcessorProvider());

    signTestInstance("XML Signature, RSA-SAH256, BES with AdES object", handler,
      getSignRequest(TestAlgorithms.getRsaSha256(), List.of(
        getRequestedSignatureTask(TestData.tbsDataXmlAdes01, SignatureType.XML, AdESType.BES, TestData.signatureId01,
          TestData.reqAdesObject01, null)
      )), testRSACredential, null, null);

    signTestInstance("XML Signature, ECDSA-SAH256, BES with AdES object", handler,
      getSignRequest(TestAlgorithms.getEcdsaSha256(), List.of(
        getRequestedSignatureTask(TestData.tbsDataXmlNoAdes, SignatureType.XML, AdESType.BES, TestData.signatureId01,
          null, null)
      )), testECCredential, null, null);

    signTestInstance("XML Signature, ECDSA-SAH256, BES no AdES object", handler,
      getSignRequest(TestAlgorithms.getEcdsaSha256(), List.of(
        getRequestedSignatureTask(TestData.tbsDataXmlNoAdes, SignatureType.XML, null, TestData.signatureId01,
          null, null)
      )), testECCredential, null, null);

    signTestInstance("XML Signature, ECDSA-SAH256, no AdES", handler,
      getSignRequest(TestAlgorithms.getEcdsaSha256(), List.of(
        getRequestedSignatureTask(TestData.tbsDataXmlNoAdes, SignatureType.XML, null, TestData.signatureId01,
          null, null)
      )), testECCredential, null, null);

    signTestInstance("XML and PDF Signature, ECDSA-SAH256, no AdES", handler,
      getSignRequest(TestAlgorithms.getEcdsaSha256(), List.of(
        getRequestedSignatureTask(TestData.tbsDataXmlNoAdes, SignatureType.XML, null, TestData.signatureId01,
          null, null),
        getRequestedSignatureTask(TestData.tbsDataPdfBes01, SignatureType.PDF, AdESType.BES, null, null, null)
      )), testECCredential, null, null);

    // Error tests
    SignatureAlgorithm badSigAlgo = mock(SignatureAlgorithm.class);
    when(badSigAlgo.getUri()).thenReturn("http://example.com/bad/algorithm");

    signTestInstance("Bad signature algorithm", handler,
      getSignRequest(badSigAlgo, List.of(
        getRequestedSignatureTask(TestData.tbsDataPdfBes01, SignatureType.PDF, AdESType.BES, null, null, null)
      )), testECCredential, null, SignatureException.class);

    signTestInstance("Blacklisted signature algorithm", handler,
      getSignRequest(TestAlgorithms.ecdsaSha1, List.of(
        getRequestedSignatureTask(TestData.tbsDataPdfBes01, SignatureType.PDF, AdESType.BES, null, null, null)
      )), testECCredential, null, SignatureException.class);

    signTestInstance("Not a signature algorithm", handler,
      getSignRequest(TestAlgorithms.sha256, List.of(
        getRequestedSignatureTask(TestData.tbsDataPdfBes01, SignatureType.PDF, AdESType.BES, null, null, null)
      )), testECCredential, null, SignatureException.class);

    signTestInstance("Invalid sign task", handler,
      getSignRequest(TestAlgorithms.getEcdsaSha256(), List.of(
        getRequestedSignatureTask("aWxsZWdhbHRic2RhdGE=", SignatureType.XML, null, null, null, null)
      )), testECCredential, null, SignatureException.class);

    signTestInstance("Invalid key type", handler,
      getSignRequest(TestAlgorithms.getEcdsaSha256(), List.of(
        getRequestedSignatureTask(TestData.tbsDataXmlNoAdes, SignatureType.XML, AdESType.BES, TestData.signatureId01,
          null, null)
      )), testRSACredential, null, SignatureException.class);
  }

  private void signTestInstance(String description, SignatureHandler signatureHandler,
    SignRequestMessage signRequestMessage,
    PkiCredential credential, SignServiceContext context, Class<? extends Exception> exClass) throws Exception {

    log.info("Sign test: " + description);

    if (exClass != null) {
      Exception exception = assertThrows(exClass, () -> {
        for (RequestedSignatureTask signatureTask : signRequestMessage.getSignatureTasks()) {
          signatureHandler.sign(signatureTask, credential, signRequestMessage, context);
        }
      });
      log.info("Caught expected exception: {}", exception.toString());
      return;
    }

    for (RequestedSignatureTask signatureTask : signRequestMessage.getSignatureTasks()) {
      CompletedSignatureTask signData = signatureHandler.sign(signatureTask, credential, signRequestMessage, context);
      log.info("Completed signature operation");
      log.info("Signature type {}, Algorithm {}, AdES {}", signData.getSignatureType(),
        signData.getSignatureAlgorithmUri(), signData.getAdESType() == null ? "None" : signData.getAdESType());
      log.info("Signature value:\n{}", TestUtils.base64Print(signData.getSignature()));
      log.info("To Be Signed bytes:\n{}", TestUtils.base64Print(signData.getTbsData()));
      if (signData.getAdESType() != null && signData.getSignatureType().equals(SignatureType.XML)) {
        assertNotNull(signData.getAdESObject());
        assertNotNull(signData.getAdESObject().getSignatureId());
        assertNotNull(signData.getAdESObject().getObjectBytes());
        log.info("XML AdES signature id: {}", signData.getAdESObject().getSignatureId());
        log.info("XML AdES object:\n{}", TestUtils.base64Print(signData.getAdESObject().getObjectBytes()));
      }
    }
  }

  private void checkRequirementsTestInstance(
    String description, SignatureHandler signatureHandler, SignRequestMessage signRequest,
    SignServiceContext serviceContext, Class<? extends Exception> exClass)
    throws InvalidRequestException {

    log.info("Signature handler test: " + description);

    if (exClass != null) {
      Exception exception = assertThrows(exClass,
        () -> signatureHandler.checkRequirements(signRequest, serviceContext));

      assertTrue(exClass.isAssignableFrom(exception.getClass()));
      log.info("Requirement check resulted in expected exception: {}", exception.toString());
      return;
    }

    // No exception
    signatureHandler.checkRequirements(signRequest, serviceContext);
    log.info("Passed requirements test");

  }

  SignRequestMessage getSignRequest(Algorithm signatureAlgorithm,
    List<RequestedSignatureTask> signatureTaskList) {
    String signatureAlgorithmUri = signatureAlgorithm == null ? null : signatureAlgorithm.getUri();
    SignRequestMessage signRequestMessage = mock(SignRequestMessage.class);
    SignatureRequirements signatureRequirements = mock(SignatureRequirements.class);
    when(signatureRequirements.getSignatureAlgorithm()).thenReturn(signatureAlgorithmUri);
    when(signRequestMessage.getSignatureRequirements()).thenReturn(signatureRequirements);
    when(signRequestMessage.getSignatureTasks()).thenReturn(signatureTaskList);
    return signRequestMessage;
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

}
