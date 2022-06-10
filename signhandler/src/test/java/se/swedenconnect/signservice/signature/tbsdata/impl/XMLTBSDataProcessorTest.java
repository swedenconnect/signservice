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

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
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

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
class XMLTBSDataProcessorTest {

  static PkiCredential testECCredential;
  static PkiCredential testRSACredential;

  static String tbsData01 =
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

  static String signatureId01 = "id-87db0dfc8e58c29471da934c194910b3";

  @BeforeAll
  static void setUp() {
    org.apache.xml.security.Init.init();
    testECCredential = new BasicCredential(TestCredentials.ecCertificate, TestCredentials.privateECKey);
    testRSACredential = new BasicCredential(TestCredentials.rsaCertificate, TestCredentials.privateRSAKey);
  }

  @Test
  void getTBSData() throws Exception {

    XMLTBSDataProcessor tbsdp = new XMLTBSDataProcessor();
    tbsdp.setIncludeIssuerSerial(true);

    TBSProcessingData tbsDataWithObj = tbsdp.getTBSData(
      getRequestedSignatureTask(tbsData01, SignatureType.XML, AdESType.BES, signatureId01, reqAdesObject01, null),
      testECCredential,
      TestAlgorithms.getEcdsaSha256()
    );

    TBSProcessingData tbsData = tbsdp.getTBSData(
      getRequestedSignatureTask(tbsData01, SignatureType.XML, AdESType.BES, signatureId01, null, null),
      testECCredential,
      TestAlgorithms.getEcdsaSha256()
    );


    assertEquals(1, 1);

  }

  private RequestedSignatureTask getRequestedSignatureTask(String tbsDataB64, SignatureType signatureType,
    AdESType adESType, String sigId, String adesObjData, String processingRules) {
    DefaultRequestedSignatureTask signatureTask = new DefaultRequestedSignatureTask();
    signatureTask.setTaskId("id01");
    signatureTask.setSignatureType(signatureType);
    signatureTask.setTbsData(Base64.decode(tbsDataB64));
    signatureTask.setAdESType(adESType);
    signatureTask.setAdESObject(new DefaultAdESObject(sigId, adesObjData == null ? null : Base64.decode(adesObjData)));
    signatureTask.setProcessingRulesUri(processingRules);
    return signatureTask;
  }
}