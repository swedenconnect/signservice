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
package se.swedenconnect.signservice.signature.tbsdata;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.signature.impl.DefaultAdESObject;

/**
 * To Be Signed processing data tests
 */
class TBSProcessingDataTest {

  @Test
  void getterAndSetterTests() {

    TBSProcessingData pd01 = TBSProcessingData.builder()
      .adesObject(new DefaultAdESObject("id01", null))
      .processingRules("pr")
      .tbsBytes(new byte[] { 0x00 })
      .build();

    assertEquals("id01", pd01.getAdesObject().getSignatureId());
    assertEquals("pr", pd01.getProcessingRules());
    assertArrayEquals(new byte[] { 0x00 }, pd01.getTbsBytes());

    TBSProcessingData pd02 = new TBSProcessingData();
    pd02.setAdesObject(new DefaultAdESObject("id01", null));
    pd02.setProcessingRules("pr");
    pd02.setTbsBytes(new byte[] { 0x00 });

    assertEquals("id01", pd02.getAdesObject().getSignatureId());
    assertEquals("pr", pd02.getProcessingRules());
    assertArrayEquals(new byte[] { 0x00 }, pd02.getTbsBytes());

  }
}