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
package se.swedenconnect.signservice.signature.impl;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;

/**
 * Test cases for DefaultSignatureHandler.
 */
@Slf4j
public class DefaultSignatureHandlerTest {

  @Test
  public void testName() {
    log.info("DefaultSignatureHandler tests");
    final DefaultSignatureHandler handler = new DefaultSignatureHandler(AlgorithmRegistrySingleton.getInstance());
    Assertions.assertEquals(DefaultSignatureHandler.DEFAULT_NAME, handler.getName());

    handler.setName("the-name");
    Assertions.assertEquals("the-name", handler.getName());
  }

}
