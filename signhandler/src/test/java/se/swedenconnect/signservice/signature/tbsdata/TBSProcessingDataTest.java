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

import org.junit.jupiter.api.Test;
import se.swedenconnect.signservice.signature.impl.DefaultAdESObject;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
class TBSProcessingDataTest {

  @Test
  void getterAndSetterTests() {

    TBSProcessingData pd01 = TBSProcessingData.builder()
      .adESObject(new DefaultAdESObject("id01", null))
      .processingRules("pr")
      .tBSBytes(new byte[] { 0x00 })
      .build();

    assertEquals("id01", pd01.getAdESObject().getSignatureId());
    assertEquals("pr", pd01.getProcessingRules());
    assertArrayEquals(new byte[]{0x00}, pd01.getTBSBytes());

    TBSProcessingData pd02 = new TBSProcessingData();
    pd02.setAdESObject(new DefaultAdESObject("id01", null));
    pd02.setProcessingRules("pr");
    pd02.setTBSBytes(new byte[]{0x00});

    assertEquals("id01", pd02.getAdESObject().getSignatureId());
    assertEquals("pr", pd02.getProcessingRules());
    assertArrayEquals(new byte[]{0x00}, pd02.getTBSBytes());


  }
}