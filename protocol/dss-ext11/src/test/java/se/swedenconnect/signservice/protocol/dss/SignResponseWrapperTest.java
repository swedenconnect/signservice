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
package se.swedenconnect.signservice.protocol.dss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for SignResponseWrapper.
 */
public class SignResponseWrapperTest {

  @Test
  public void testJavaSerialization() throws Exception {

    final SignResponseWrapper w1 = new SignResponseWrapper();
    w1.setRequestID("ABC");
    w1.setProfile("foo");

    // Serialize
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    ObjectOutputStream out = new ObjectOutputStream(bos);
    out.writeObject(w1);
    byte[] serialization = bos.toByteArray();
    Assertions.assertNotNull(serialization);

    // Deserialize
    ByteArrayInputStream bis = new ByteArrayInputStream(serialization);
    ObjectInputStream in = new ObjectInputStream(bis);
    final SignResponseWrapper w2 = (SignResponseWrapper) in.readObject();
    Assertions.assertNotNull(w2);
    Assertions.assertEquals(w1.getRequestID(), w2.getRequestID());
    Assertions.assertEquals(w1.getProfile(), w2.getProfile());
  }

}
