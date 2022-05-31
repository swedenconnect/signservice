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

package se.swedenconnect.signservice.certificate.base.attributemapping;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.junit.jupiter.api.Test;
import se.swedenconnect.signservice.certificate.CertificateAttributeType;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * AttributeMappingData test
 */
@Slf4j
class AttributeMappingDataTest {

  @Test
  void attributeMappingDataTest() {
    log.info("Attribute mapping data test");
    AttributeMappingData attributeMappingData = AttributeMappingData.builder()
      .sourceId("id")
      .sourceFriendlyName("friendlyName")
      .value("value")
      .defaultValue(true)
      .certificateAttributeType(CertificateAttributeType.RDN)
      .reference("ref")
      .build();

    assertEquals("id", attributeMappingData.getSourceId());
    assertEquals("value", attributeMappingData.getValue());
    assertEquals("friendlyName", attributeMappingData.getSourceFriendlyName());
    assertTrue(attributeMappingData.isDefaultValue());
    assertEquals(CertificateAttributeType.RDN, attributeMappingData.getCertificateAttributeType());
    assertEquals("ref", attributeMappingData.getReference());


    AttributeMappingData noArgsConstructed = new AttributeMappingData();
    noArgsConstructed.setCertificateAttributeType(CertificateAttributeType.RDN);
    noArgsConstructed.setSourceId("id");
    noArgsConstructed.setDefaultValue(true);
    noArgsConstructed.setReference("ref");
    noArgsConstructed.setSourceFriendlyName("friendlyName");
    noArgsConstructed.setValue("value");

    assertEquals("id", noArgsConstructed.getSourceId());
    assertEquals("value", noArgsConstructed.getValue());
    assertEquals("friendlyName", noArgsConstructed.getSourceFriendlyName());
    assertTrue(noArgsConstructed.isDefaultValue());
    assertEquals(CertificateAttributeType.RDN, noArgsConstructed.getCertificateAttributeType());
    assertEquals("ref", noArgsConstructed.getReference());


    AttributeMappingData allArgsConstructed = new AttributeMappingData(CertificateAttributeType.RDN, "ref", "id", "friendlyName", true, "value");

    assertEquals("id", allArgsConstructed.getSourceId());
    assertEquals("value", allArgsConstructed.getValue());
    assertEquals("friendlyName", allArgsConstructed.getSourceFriendlyName());
    assertTrue(allArgsConstructed.isDefaultValue());
    assertEquals(CertificateAttributeType.RDN, allArgsConstructed.getCertificateAttributeType());
    assertEquals("ref", allArgsConstructed.getReference());

    assertTrue(StringUtils.isNotBlank(allArgsConstructed.toString()));
    assertTrue(allArgsConstructed.equals(allArgsConstructed));
    assertTrue(allArgsConstructed.hashCode() != 0);
  }
}