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
package se.swedenconnect.signservice.protocol.dss;

import org.apache.commons.lang3.SerializationUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import se.idsec.signservice.xml.DOMUtils;
import se.swedenconnect.schemas.csig.dssext_1_1.SignMessage;
import se.swedenconnect.xml.jaxb.JAXBUnmarshaller;

/**
 * Test cases for DssSignMessage.
 */
public class DssSignMessageTest {

  @Test
  public void testUsage() throws Exception {
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/signMessage.xml"));
    final SignMessage sm = JAXBUnmarshaller.unmarshall(doc, SignMessage.class);

    final DssSignMessage dssSignMessage = new DssSignMessage(sm);

    Assertions.assertNotNull(dssSignMessage.getEncoding());
    Assertions.assertNotNull(dssSignMessage.getDssSignMessage());
    Assertions.assertTrue(dssSignMessage.getMustShow());

    // Assert that we can create a SignMessage from the encoding
    final SignMessage fromEncoding = JAXBUnmarshaller.unmarshall(DOMUtils.bytesToDocument(dssSignMessage.getEncoding()),
        se.swedenconnect.schemas.csig.dssext_1_1.SignMessage.class);
    Assertions.assertNotNull(fromEncoding);

    // Serialize and deserialize
    final DssSignMessage dssSignMessage2 = SerializationUtils.roundtrip(dssSignMessage);

    Assertions.assertArrayEquals(dssSignMessage.getEncoding(), dssSignMessage2.getEncoding());
    Assertions.assertNotNull(dssSignMessage2.getDssSignMessage());
  }

}
