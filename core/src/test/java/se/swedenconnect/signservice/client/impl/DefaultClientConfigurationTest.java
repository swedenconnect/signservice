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
package se.swedenconnect.signservice.client.impl;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.idsec.signservice.security.certificate.CertificateUtils;

/**
 * Test cases for DefaultClientConfiguration.
 */
public class DefaultClientConfigurationTest {

  private final static String cert =
      "-----BEGIN CERTIFICATE-----\n" +
          "MIIDKTCCAhECBgFpWR1N1TANBgkqhkiG9w0BAQ0FADBYMQswCQYDVQQGEwJTRTEX\n" +
          "MBUGA1UEChMOU3dlZGVuIENvbm5lY3QxMDAuBgNVBAMTJ1N3ZWRlbiBDb25uZWN0\n" +
          "IFNhbmRib3ggTWV0YWRhdGEgU2VydmljZTAeFw0xOTAzMDcxNTA0NDZaFw0yOTAz\n" +
          "MTQxNDMxMjlaMFgxCzAJBgNVBAYTAlNFMRcwFQYDVQQKEw5Td2VkZW4gQ29ubmVj\n" +
          "dDEwMC4GA1UEAxMnU3dlZGVuIENvbm5lY3QgU2FuZGJveCBNZXRhZGF0YSBTZXJ2\n" +
          "aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhsaz2wrmWHjGZ4sD\n" +
          "gCDtTIkIxg9yyH2iwXXTbnLAFa8aWFu22DMM74C9hqeMleiMgMeZFIBz4xJBBCIx\n" +
          "/jYcWHQoQ/IlgZC7mjpMcmDVxYxUNwD5OZKj/gQfnz/KXlpShl+ktpn3Ae3jmw0K\n" +
          "m9vKLH1xPm2pOF9qzX+YvmMfVXVwaUYQ8ZO7pg3Vk0iZXPmQsVlLd5XXOfP7FyIA\n" +
          "M1VpOPQNxiLzh5QVYJv+YN8s1PR58Q9X8jik/jZBeSfZozNMfEIPSv2Xqd59cZm/\n" +
          "JGf73Ecb/gKLpxg3e8P0FlvOLD3oMkh6puRpC0oMAet5yWa+cEvqqE/bE6KAjNAI\n" +
          "QYWNRQIDAQABMA0GCSqGSIb3DQEBDQUAA4IBAQBKZiBAJ8A3MzdWMcU9o3CBcx+r\n" +
          "RUoZQ+HSMJHDLd6iO0RZqD1eTngzFcOShKKZtttxkYyEY3RcTyOQPojmqZOCSLzJ\n" +
          "oBF/wjc6URIxXM7hWdzDAyoakVU7xdkrSes5JEcSJ+e0Mjl5jkLi5V7LYlMUsJuP\n" +
          "FRd+ktD89Vnsebgb+4bE4flrhv3XvwUkPCCHmogN/oTUMrBV4qh61Gtdty/DS+XY\n" +
          "u+RuTyE+kyrGp8hnrpjew6+arulJWNKqcGd+isdixcdA0Lr8IxwkfEOGUCKWtOHZ\n" +
          "+Bs/Gge2sVyrWwb3UQarAf32KawhI4mG2icWc3KcfLEt7NxUOws/InQV8Sd3\n" +
          "-----END CERTIFICATE-----";

  @Test
  public void testNullCtor() {
    Assertions.assertThrows(NullPointerException.class, () -> {
      new DefaultClientConfiguration(null);
    });
  }

  @Test
  public void testUsage() throws CertificateException {
    final DefaultClientConfiguration c1 = new DefaultClientConfiguration("clientID");
    Assertions.assertEquals("clientID", c1.getClientId());
    Assertions.assertNull(c1.getTrustedCertificates());
    Assertions.assertNull(c1.getResponseUrls());
    Assertions.assertEquals("client-id='clientID', trusted-certificates=[], response-urls=[]", c1.toString());

    final X509Certificate c = CertificateUtils.decodeCertificate(new ByteArrayInputStream(cert.getBytes()));

    final DefaultClientConfiguration c2 = new DefaultClientConfiguration("clientID");
    c2.setResponseUrls(Arrays.asList("https://sign.example.com", "https://sign2.example.com"));
    c2.setTrustedCertificates(Arrays.asList(c));

    Assertions.assertEquals("clientID", c2.getClientId());
    Assertions.assertTrue(c2.getTrustedCertificates().size() == 1);
    Assertions.assertEquals(Arrays.asList("https://sign.example.com", "https://sign2.example.com"), c2.getResponseUrls());
    Assertions.assertNotNull(c2.toString());
  }

}
