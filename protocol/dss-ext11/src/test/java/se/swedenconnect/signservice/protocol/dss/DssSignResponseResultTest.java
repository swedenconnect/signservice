/*
 * Copyright 2022-2024 Sweden Connect
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
package se.swedenconnect.signservice.protocol.dss;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.idsec.signservice.dss.DSSStatusCodes;
import se.swedenconnect.schemas.dss_1_0.InternationalStringType;
import se.swedenconnect.schemas.dss_1_0.Result;
import se.swedenconnect.signservice.engine.SignServiceError;
import se.swedenconnect.signservice.engine.SignServiceErrorCode;

/**
 * Test cases for DssSignResponseResult
 */
public class DssSignResponseResultTest {

  @Test
  public void testSuccess() {
    final DssSignResponseResult result = new DssSignResponseResult();
    Assertions.assertTrue(result.isSuccess());
    Assertions.assertEquals(DSSStatusCodes.DSS_SUCCESS, result.getErrorCode());
    Assertions.assertNull(result.getMinorErrorCode());
    Assertions.assertNull(result.getMessage());
    Assertions.assertEquals(String.format("result-major='%s'", DSSStatusCodes.DSS_SUCCESS), result.toString());
  }

  @Test
  public void testFromResult() {
    final Result jaxb = new Result();
    jaxb.setResultMajor("abc");
    jaxb.setResultMinor("def");
    final InternationalStringType msg = new InternationalStringType();
    msg.setLang("en");
    msg.setValue("message");
    jaxb.setResultMessage(msg);

    final DssSignResponseResult result = new DssSignResponseResult(jaxb);
    Assertions.assertFalse(result.isSuccess());
    Assertions.assertEquals("abc", result.getErrorCode());
    Assertions.assertEquals("def", result.getMinorErrorCode());
    Assertions.assertEquals("message", result.getMessage());
    Assertions.assertEquals("result-major='abc', result-minor='def', result-message='message'", result.toString());
  }

  @Test
  public void testFromSignServiceError() {
    for (final SignServiceErrorCode c : SignServiceErrorCode.values()) {
      final DssSignResponseResult result = new DssSignResponseResult(new SignServiceError(c));
      Assertions.assertFalse(result.isSuccess());
      Assertions.assertNotNull(result.getErrorCode());
      Assertions.assertNotNull(result.getMinorErrorCode());
      Assertions.assertEquals(c.getDefaultMessage(), result.getMessage());
    }
  }

}
