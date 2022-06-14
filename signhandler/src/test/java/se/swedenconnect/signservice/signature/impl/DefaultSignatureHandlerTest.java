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
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.msg.SignatureRequirements;
import se.swedenconnect.signservice.session.SignServiceContext;
import se.swedenconnect.signservice.signature.AdESType;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;
import se.swedenconnect.signservice.signature.SignatureHandler;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.signer.TestAlgorithms;
import se.swedenconnect.signservice.signature.signer.TestCredentials;
import se.swedenconnect.signservice.signature.signer.impl.DefaultSignServiceSignerProvider;
import se.swedenconnect.signservice.signature.tbsdata.impl.DefaultTBSDataProcessorProvider;
import se.swedenconnect.signservice.signature.testutils.TestData;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test cases for DefaultSignatureHandler.
 */
@Slf4j
public class DefaultSignatureHandlerTest {

  static AlgorithmRegistry algorithmRegistry;
  static PkiCredential testECCredential;
  static PkiCredential testRSACredential;

  @BeforeAll
  static void setup() {
    algorithmRegistry = AlgorithmRegistrySingleton.getInstance();
    testECCredential = new BasicCredential(TestCredentials.ecCertificate, TestCredentials.privateECKey);
    testRSACredential = new BasicCredential(TestCredentials.rsaCertificate, TestCredentials.privateRSAKey);
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

    // TODO run tests
    signTestInstance("Test", handler,
      getSignRequest(TestAlgorithms.getRsaSha256(), List.of(
        getRequestedSignatureTask(TestData.tbsDataXmlAdes01, SignatureType.XML, AdESType.BES, TestData.signatureId01,
          TestData.tbsDataXmlAdes01, null)
      )), testRSACredential, null, null);
  }

  private void signTestInstance(String description, SignatureHandler signatureHandler, SignRequestMessage signRequestMessage,
    PkiCredential credential, SignServiceContext context, Class<? extends Exception> exClass) throws Exception {

    // TODO Individual test

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

  SignRequestMessage getSignRequest(SignatureAlgorithm signatureAlgorithm,
    List<RequestedSignatureTask> signatureTaskList) {
    SignRequestMessage signRequestMessage = mock(SignRequestMessage.class);
    SignatureRequirements signatureRequirements = mock(SignatureRequirements.class);
    when(signatureRequirements.getSignatureAlgorithm()).thenReturn(
      signatureAlgorithm == null ? null : signatureAlgorithm.getUri());
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
