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

package se.swedenconnect.signservice.certificate.attributemapping;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.jupiter.api.Test;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.authn.impl.SimpleAuthnContextIdentifier;
import se.swedenconnect.signservice.certificate.CertificateAttributeType;
import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.attribute.IdentityAttributeIdentifier;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.msg.CertificateAttributeMapping;
import se.swedenconnect.signservice.protocol.msg.SignatureRequirements;
import se.swedenconnect.signservice.protocol.msg.SigningCertificateRequirements;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultCertificateAttributeMapping;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultRequestedCertificateAttribute;

/**
 * Test for the default attribute mapper.
 */
@Slf4j
class DefaultAttributeMapperTest {

  @Test
  void getMappedCertAttributes() throws Exception {

    log.info("Attribute mapping tests");
    AttributeMapper attributeMapper = new DefaultAttributeMapper(new DefaultValuePolicyChecker() {
      @Override public boolean isDefaultValueAllowed(CertificateAttributeType attributeType, String ref, String value) {
        return attributeType.equals(CertificateAttributeType.RDN) && ref.equalsIgnoreCase("2.5.4.6") && value.equalsIgnoreCase("SE");
      }
    });

    AttributeMapper noDefaultsAttributeMapper = new DefaultAttributeMapper(new DefaultValuePolicyChecker() {
      @Override public boolean isDefaultValueAllowed(CertificateAttributeType attributeType, String ref, String value) {
        return false;
      }
    });

    List<AttributeMappingData> mappedCertAttributes = attributeMapper.mapCertificateAttributes(getSignRequest(
      XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
      "client01", CertificateType.PKC,
      null, TestData.allAttributeMappings
    ), TestData.stdAssertion);

    assertEquals(7, mappedCertAttributes.size());
    checkAttribute(mappedCertAttributes, BCStyle.DATE_OF_BIRTH.getId(), CertificateAttributeType.SDA, "1992-05-15");
    checkAttribute(mappedCertAttributes, "2", CertificateAttributeType.SAN, "example.com");
    checkAttribute(mappedCertAttributes, BCStyle.SERIALNUMBER.getId(), CertificateAttributeType.RDN, "1234567890");
    checkAttribute(mappedCertAttributes, BCStyle.GIVENNAME.getId(), CertificateAttributeType.RDN, "Nisse");
    checkAttribute(mappedCertAttributes, BCStyle.SURNAME.getId(), CertificateAttributeType.RDN, "Hult");
    checkAttribute(mappedCertAttributes, BCStyle.CN.getId(), CertificateAttributeType.RDN, "Nisse Hult");

    log.info("Successfully mapped attributes");

    AttributeMappingException exception = assertThrows(AttributeMappingException.class,
      () -> noDefaultsAttributeMapper.mapCertificateAttributes(getSignRequest(
        XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
        "client01", CertificateType.PKC,
        null, TestData.allAttributeMappings
      ), TestData.stdAssertion));

    log.info("Caught exception when mapping without allowing default C values: {}", exception.toString());

  }

  private void checkAttribute(List<AttributeMappingData> mappedCertAttributes, String ref, CertificateAttributeType type, String val) {
    AttributeMappingData attrData = mappedCertAttributes.stream()
      .filter(attributeMappingData -> attributeMappingData.getReference().equalsIgnoreCase(ref))
      .findFirst()
      .orElseThrow(() -> new IllegalArgumentException("Attribute " + ref + " is missing from mapped attributes"));
    assertEquals(type, attrData.getCertificateAttributeType());
    assertEquals(val, attrData.getValue());
    log.info("Found attribute {} of type {} with value {}", ref, type, val);
  }


  private SignRequestMessage getSignRequest(String signatureAlgorithm, String clientId,
    CertificateType certType, String profile, List<CertificateAttributeMapping> attributeMappings) {
    SignRequestMessage signRequestMessage = mock(SignRequestMessage.class);
    SignatureRequirements signatureRequirements = mock(SignatureRequirements.class);
    SigningCertificateRequirements certificateRequirements = mock(SigningCertificateRequirements.class);
    when(signatureRequirements.getSignatureAlgorithm()).thenReturn(signatureAlgorithm);
    when(certificateRequirements.getCertificateType()).thenReturn(certType);
    when(certificateRequirements.getSigningCertificateProfile()).thenReturn(profile);
    when(certificateRequirements.getAttributeMappings()).thenReturn(attributeMappings);

    when(signRequestMessage.getSignatureRequirements()).thenReturn(signatureRequirements);
    when(signRequestMessage.getSigningCertificateRequirements()).thenReturn(certificateRequirements);
    when(signRequestMessage.getClientId()).thenReturn(clientId);
    return signRequestMessage;
  }

  static class TestData {

    static IdentityAssertion stdAssertion = getTestAssertion();
    static List<CertificateAttributeMapping> defaultAttributeMappings = getDefaultAttributeMappings(false, false);
    static List<CertificateAttributeMapping> sanAttributeMappings = getDefaultAttributeMappings(true, false);
    static List<CertificateAttributeMapping> sdaAttributeMappings = getDefaultAttributeMappings(false, true);
    static List<CertificateAttributeMapping> allAttributeMappings = getDefaultAttributeMappings(true, true);

    private static List<CertificateAttributeMapping> getDefaultAttributeMappings(boolean san, boolean sda) {
      List<CertificateAttributeMapping> attrMapList = new ArrayList<>();
      attrMapList.add(getMapping(BCStyle.SERIALNUMBER.getId(), CertificateAttributeType.RDN,
        "givenName", true, null, new String[] { "urn:oid:1.2.752.29.4.13" }));
      attrMapList.add(getMapping(BCStyle.C.getId(), CertificateAttributeType.RDN,
        "country", true, "SE", new String[] { "urn:oid:2.5.4.6" }));
      attrMapList.add(getMapping(BCStyle.GIVENNAME.getId(), CertificateAttributeType.RDN,
        "givenName", true, null, new String[] { "urn:oid:2.5.4.42" }));
      attrMapList.add(getMapping(BCStyle.SURNAME.getId(), CertificateAttributeType.RDN,
        "surname", true, null, new String[] { "urn:oid:2.5.4.4" }));
      attrMapList.add(getMapping(BCStyle.CN.getId(), CertificateAttributeType.RDN,
        "surname", true, null, new String[] { "urn:oid:2.16.840.1.113730.3.1.241", "urn:oid:2.5.4.3" }));

      if (san) {
        attrMapList.add(getMapping("2", CertificateAttributeType.SAN,
          "dnsName", false, null, new String[] { "urn:oid:" + BCStyle.DC.getId() }));
      }
      if (sda) {
        attrMapList.add(getMapping(BCStyle.DATE_OF_BIRTH.getId(), CertificateAttributeType.SDA,
          "dateOfBirth", false, null, new String[] { "urn:oid:" + BCStyle.DATE_OF_BIRTH.getId() }));
      }
      return attrMapList;
    }

    private static CertificateAttributeMapping getMapping(String identifier, CertificateAttributeType attributeType,
      String friendlyName,
      boolean required, String defaultVal, String[] sourceIdArray) {
      DefaultCertificateAttributeMapping mapping = new DefaultCertificateAttributeMapping();
      DefaultRequestedCertificateAttribute destAttr = new DefaultRequestedCertificateAttribute(
        attributeType, identifier, friendlyName);
      destAttr.setRequired(required);
      destAttr.setDefaultValue(defaultVal);
      mapping.setDestination(destAttr);
      mapping.setSources(Arrays.stream(sourceIdArray)
        .map(MappedAttrSouce::new)
        .collect(Collectors.toList()));
      return mapping;
    }

    private static IdentityAssertion getTestAssertion() {
      IdentityAssertion assertion = mock(IdentityAssertion.class);
      when(assertion.getIdentityAttributes()).thenReturn(List.of(
        getMockAttr(BCStyle.GIVENNAME.getId(), "Nisse", "Given name"),
        getMockAttr(BCStyle.SURNAME.getId(), "Hult", "Surname"),
        getMockAttr("1.2.752.29.4.13", "1234567890", "Personal identity number"),
        getMockAttr(BCStyle.CN.getId(), "Nisse Hult", "Common name"),
        getMockAttr(BCStyle.DC.getId(), "example.com", "DNS name"),
        getMockAttr(BCStyle.GENDER.getId(), "M", "Gender"),
        getMockAttr(BCStyle.DATE_OF_BIRTH.getId(), "1992-05-15", "Gender")
      ));
      when(assertion.getIdentifier()).thenReturn("a092384092384092384092834098234092834");
      when(assertion.getAuthnContext()).thenReturn(
        new SimpleAuthnContextIdentifier("http://id.elegnamnden.se/loa/1.0/loa3"));
      when(assertion.getIssuer()).thenReturn("http://id.swedenconnect.se/idp");
      when(assertion.getAuthnInstant()).thenReturn(Instant.ofEpochMilli(System.currentTimeMillis()));
      return assertion;
    }

    private static IdentityAttribute<?> getMockAttr(String oidString, String value, String friendlyName) {
      return new StringSamlIdentityAttribute("urn:oid:" + oidString, friendlyName, value);
    }

  }

  @Data
  static class MappedAttrSouce implements IdentityAttributeIdentifier {

    private static final long serialVersionUID = 8310812144208550689L;

    public MappedAttrSouce(String identifier) {
      this.identifier = identifier;
    }

    String scheme;
    String identifier;
    String friendlyName;
  }
}