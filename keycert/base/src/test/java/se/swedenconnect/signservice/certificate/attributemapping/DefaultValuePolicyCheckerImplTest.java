/*
 * Copyright 2022-2025 Sweden Connect
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

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.certificate.CertificateAttributeType;
import se.swedenconnect.signservice.certificate.attributemapping.DefaultValuePolicyCheckerImpl.DefaultValuePolicyCheckerConfig;

/**
 * Test cases for DefaultValuePolicyCheckerImpl.
 */
public class DefaultValuePolicyCheckerImplTest {

  @Test
  public void testDefaults() {
    final DefaultValuePolicyCheckerImpl checker1 = new DefaultValuePolicyCheckerImpl(null, true);
    Assertions.assertTrue(checker1.isDefaultValueAllowed(CertificateAttributeType.RDN, "2.5.4.6", "SE"));

    final DefaultValuePolicyCheckerImpl checker2 = new DefaultValuePolicyCheckerImpl(null, false);
    Assertions.assertFalse(checker2.isDefaultValueAllowed(CertificateAttributeType.RDN, "2.5.4.6", "SE"));
  }

  @Test
  public void testUsage() {
    DefaultValuePolicyCheckerConfig cc = DefaultValuePolicyCheckerConfig.builder()
        .allowAnyValue(false)
        .allowedValues(Arrays.asList("SE", "NO"))
        .attributeType(CertificateAttributeType.RDN)
        .ref("2.5.4.6")
        .build();

    final DefaultValuePolicyCheckerImpl checker = new DefaultValuePolicyCheckerImpl(Arrays.asList(cc), false);

    Assertions.assertTrue(
        checker.isDefaultValueAllowed(CertificateAttributeType.RDN, "2.5.4.6", "SE"));
    Assertions.assertTrue(
        checker.isDefaultValueAllowed(CertificateAttributeType.RDN, "2.5.4.6", "NO"));
    Assertions.assertFalse(
        checker.isDefaultValueAllowed(CertificateAttributeType.RDN, "2.5.4.6", "DK"));
    Assertions.assertFalse(
        checker.isDefaultValueAllowed(CertificateAttributeType.RDN, "2.5.4.7", "SE"));
    Assertions.assertFalse(
        checker.isDefaultValueAllowed(CertificateAttributeType.SAN, "foobar", "SE"));

    final DefaultValuePolicyCheckerImpl checker2 =
        new DefaultValuePolicyCheckerImpl(Arrays.asList(DefaultValuePolicyCheckerConfig.builder()
            .allowAnyValue(false)
            .attributeType(CertificateAttributeType.RDN)
            .ref("2.5.4.6")
            .build()), false);
    Assertions.assertFalse(
        checker2.isDefaultValueAllowed(CertificateAttributeType.RDN, "2.5.4.6", "SE"));

    final DefaultValuePolicyCheckerImpl checker3 =
        new DefaultValuePolicyCheckerImpl(Arrays.asList(DefaultValuePolicyCheckerConfig.builder()
            .allowAnyValue(false)
            .allowedValues(Collections.emptyList())
            .attributeType(CertificateAttributeType.RDN)
            .ref("2.5.4.6")
            .build()), false);
    Assertions.assertFalse(
        checker3.isDefaultValueAllowed(CertificateAttributeType.RDN, "2.5.4.6", "SE"));
  }

  @Test
  public void testInvalidInput() {
    final DefaultValuePolicyCheckerImpl checker = new DefaultValuePolicyCheckerImpl(null, true);
    assertThatThrownBy(() -> {
      checker.isDefaultValueAllowed(null, "2.5.4.6", "SE");
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Invalid input");
    assertThatThrownBy(() -> {
      checker.isDefaultValueAllowed(CertificateAttributeType.RDN, null, "SE");
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Invalid input");
    assertThatThrownBy(() -> {
      checker.isDefaultValueAllowed(CertificateAttributeType.RDN, "", "SE");
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Invalid input");
    assertThatThrownBy(() -> {
      checker.isDefaultValueAllowed(CertificateAttributeType.RDN, "2.5.4.6", null);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Invalid input");
    assertThatThrownBy(() -> {
      checker.isDefaultValueAllowed(CertificateAttributeType.RDN, "2.5.4.6", "");
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Invalid input");
  }

}
