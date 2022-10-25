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
package se.swedenconnect.signservice.signature.testutils;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.util.encoders.Base64;
import se.swedenconnect.signservice.signature.tbsdata.impl.PDFTBSDataProcessor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Test data
 */
public class TestData {

  public static String tbsDataPdfBes01 =
    "MYG/MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwKgYJKoZIhvcNAQk0MR0wGzANBglghkgBZQMEAgEFAKEKBggqhkjOPQQ"
      + "DAjAvBgkqhkiG9w0BCQQxIgQglmTHu8re0Yh3ExDB4DUcAj/YbYbnooAzFRdcGkMluXwwRgYLKoZIhvcNAQkQAi8xNzA1MDMwMTANBglghkgB"
      + "ZQMEAgEFAAQg89vSUeiLpG0FVF29g5cyBTLK7yzk6sQ+AWWuDcZIq6g=";
  public static String tbsDataPdf01 =
    "MYGTMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIyMDYwODIxMzY1NFowKAYJKo"
      + "ZIhvcNAQk0MRswGTALBglghkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIP0H2n2cZU2crfQnF6BNSe19mvABX8ojfUB+LwBGFBbp";
  public static String resultTbsDataPdfBes01 =
    "MYGuMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwKAYJKoZIhvcNAQk0MRswGTALBglghkgBZQMEAgGh"
      + "CgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIJZkx7vK3tGIdxMQweA1HAI/2G2G56KAMxUXXBpDJbl8"
      + "MDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIDbOxe9Zse1ViwENx9TFQDgn6oke9ptxkGtdDW50+FeQ";
  public static String resultTbsDataPdfBesSha1 =
    "MYGfMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwJQYJKoZIhvcNAQk0MRgwFjAJBgUrDgMCGgUA"
      + "oQkGByqGSM49BAEwKwYLKoZIhvcNAQkQAgwxHDAaMBgwFgQU5XNXi5/RbgjvgmA9Dvdiayvp8j0wLwYJKoZIhvcNAQkEMSIEIJZkx7vK3tGIdxMQ"
      + "weA1HAI/2G2G56KAMxUXXBpDJbl8";
  public static String resultTbsDataPdfBesIssuerSerial =
    "MYIBKjAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMCgGCSqGSIb3DQEJNDEbMBkwCwYJYIZIAWUDBAIBoQoGCCqGSM49BAM"
      + "CMC8GCSqGSIb3DQEJBDEiBCCWZMe7yt7RiHcTEMHgNRwCP9hthueigDMVF1waQyW5fDCBsgYLKoZIhvcNAQkQAi8xgaIwgZ8wgZwwgZkE"
      + "IDbOxe9Zse1ViwENx9TFQDgn6oke9ptxkGtdDW50+FeQMHUwbaRrMGkxCzAJBgNVBAYTAlNFMRowGAYDVQQFExFTRVBOUi0wMTIzNDU2N"
      + "zg5MDESMBAGA1UEBRMJU2FudGVzc29uMQ8wDQYDVQQqDAZTdGVmYW4xGTAXBgNVBAMMEFN0ZWZhbiBTYW50ZXNzb24CBGEflMY=";
  public static String resultNoPadesNoTime =
    "MXUwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAoBgkqhkiG9w0BCTQxGzAZMAsGCWCGSAFlAwQCA"
      + "aEKBggqhkjOPQQDAjAvBgkqhkiG9w0BCQQxIgQg/QfafZxlTZyt9CcXoE1J7X2a8AFfyiN9QH4vAEYUFuk=";

  // XML
  public static String tbsDataXmlAdes01 =
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
  public static String reqAdesObject01 =
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
  public static String tbsDataXmlNoAdes =
    "PGRzOlNpZ25lZEluZm8geG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkc"
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

  public static String signatureId01 = "id-87db0dfc8e58c29471da934c194910b3";


  public static String fixXAdESSigTime(String adesObjectB64) {
    return fixXAdESSigTime(adesObjectB64, Instant.now());
  }

  public static String fixXAdESSigTime(String adesObjectB64, Instant time) {
    String adesObject = new String(Base64.decode(adesObjectB64), StandardCharsets.UTF_8);
    Pattern sigTimePattern = Pattern.compile("xades:SigningTime>\\S+</xades:SigningTime");
    Matcher matcher = sigTimePattern.matcher(adesObject);
    if (matcher.find()){
      String sigTimeData = matcher.group(0);
      String nowTimeString = DateTimeFormatter.ISO_OFFSET_DATE_TIME.withZone(ZoneId.systemDefault()).format(time);
      String fixedAdesObject = adesObject.replace(sigTimeData, "xades:SigningTime>" + nowTimeString + "</xades:SigningTime");
      return Base64.toBase64String(fixedAdesObject.getBytes(StandardCharsets.UTF_8));
    }
    return adesObjectB64;
  }

  public static String fixCMSSigTime(String signedAttrB64) throws IOException {
    return fixCMSSigTime(signedAttrB64, Instant.now());
  }

  public static String fixCMSSigTime(String signedAttrB64, Instant time) throws IOException {
    return fixCMSSigTime(signedAttrB64, time, false);
  }

  public static String fixCMSSigTime(String signedAttrB64, Instant time, boolean insertError) throws IOException {
    List<Attribute> attributes = PDFTBSDataProcessor.parseSignedAttributeBytes(Base64.decode(signedAttrB64));
    ASN1EncodableVector valueSetVector = new ASN1EncodableVector();
    DERUTCTime fixedTime = new DERUTCTime(Date.from(time));
    if (insertError) {
      // Generate error by inserting an OID instead of a time element
      valueSetVector.add(CMSAttributes.signingTime);
    } else {
      // Insert time
      valueSetVector.add(fixedTime);
    }
    Attribute fixedSigningTimeAttr = new Attribute(CMSAttributes.signingTime, new DERSet(valueSetVector));
    List<Attribute> fixedAttributeList = PDFTBSDataProcessor.replaceAttribute(attributes, CMSAttributes.signingTime,
      fixedSigningTimeAttr);
    ASN1EncodableVector attributeSetVector = new ASN1EncodableVector();
    for (Attribute fixedAttr : fixedAttributeList){
      attributeSetVector.add(fixedAttr);
    }
    String fixedB64SignedAttr = Base64.toBase64String(new DERSet(attributeSetVector).getEncoded(ASN1Encoding.DER));
    return fixedB64SignedAttr;
  }


}
