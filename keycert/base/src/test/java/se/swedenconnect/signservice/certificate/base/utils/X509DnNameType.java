/*
 * Copyright 2022-2023 Sweden Connect
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
package se.swedenconnect.signservice.certificate.base.utils;

import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public enum X509DnNameType {
  CN("2.5.4.3"), Surename("2.5.4.4"), GivenName("2.5.4.42"), SerialNumber("2.5.4.5"), Org("2.5.4.10"), OrgUnit(
      "2.5.4.11"), Country("2.5.4.6");

  @Getter
  private final String oidString;

  public static X509DnNameType getNameTypeForOid(ASN1ObjectIdentifier oid) {
    String oidString = oid.getId();
    return getNameTypeForOid(oidString);
  }

  public static X509DnNameType getNameTypeForOid(final String oidStringInp) {
    final String oidString = (oidStringInp.toLowerCase().startsWith("urn:oid:"))
        ? oidStringInp.substring(8)
        : oidStringInp;

    return Arrays.stream(values())
        .filter(x509DnNameType -> x509DnNameType.getOidString().equalsIgnoreCase(oidString))
        .findFirst()
        .orElse(null);
  }

  public AttributeTypeAndValue getAttribute(String oidStr) {
    return new AttributeTypeAndValue(new ASN1ObjectIdentifier(this.oidString), this.getASN1Val(oidStr));
  }

  private ASN1Encodable getASN1Val(String value) {
    boolean isASCII = this.isStringASCII(value);
    if (!isASCII && (this.equals(SerialNumber) || this.equals(Country))) {
      return null;
    }
    else {
      ASN1Encodable asn1Val;
      if (!isASCII) {
        asn1Val = new DERUTF8String(value);
      }
      else {
        asn1Val = new DERPrintableString(value);
      }
      return asn1Val;
    }
  }

  private boolean isStringASCII(String value) {
    CharsetEncoder asciiEncoder = StandardCharsets.US_ASCII.newEncoder();
    return asciiEncoder.canEncode(value);
  }
}
