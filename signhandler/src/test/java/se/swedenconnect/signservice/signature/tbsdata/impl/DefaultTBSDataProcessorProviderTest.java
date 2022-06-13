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

package se.swedenconnect.signservice.signature.tbsdata.impl;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.tbsdata.TBSDataProcessor;
import se.swedenconnect.signservice.signature.tbsdata.TBSDataProcessorProvider;

import java.security.SignatureException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test TBS data processor provider
 */
@Slf4j
class DefaultTBSDataProcessorProviderTest {

  @Test
  void getTBSDataProcessor() throws SignatureException {
    log.info("TBSDataProcessorProvider test");
    TBSDataProcessorProvider tbsDataProcessorProvider = new DefaultTBSDataProcessorProvider();

    TBSDataProcessor xmlProcessor = tbsDataProcessorProvider.getTBSDataProcessor(SignatureType.XML);
    assertEquals(XMLTBSDataProcessor.class.getSimpleName(), xmlProcessor.getClass().getSimpleName());
    log.info("Successfully obtaining XML TBS data processor");
    TBSDataProcessor pdfProcessor = tbsDataProcessorProvider.getTBSDataProcessor(SignatureType.PDF);
    assertEquals(PDFTBSDataProcessor.class.getSimpleName(), pdfProcessor.getClass().getSimpleName());
    log.info("Successfully obtaining PDF TBS data processor");

    SignatureException ex1 = assertThrows(SignatureException.class,
      () -> tbsDataProcessorProvider.getTBSDataProcessor(SignatureType.CMS));
    log.info("Exception test: {}", ex1.toString());

    NullPointerException ex2 = assertThrows(NullPointerException.class,
      () -> tbsDataProcessorProvider.getTBSDataProcessor(null));
    log.info("Exception test: {}", ex2.toString());

  }
}