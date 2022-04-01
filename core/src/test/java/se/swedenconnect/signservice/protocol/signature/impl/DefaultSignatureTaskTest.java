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
package se.swedenconnect.signservice.protocol.signature.impl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.signature.AdESType;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.impl.DefaultAdESObject;
import se.swedenconnect.signservice.signature.impl.DefaultSignatureTask;

/**
 * Test cases for DefaultSignatureTask.
 */
public class DefaultSignatureTaskTest {

  @Test
  public void testUsage() {
    DefaultSignatureTask task = new DefaultSignatureTask();

    task.setTaskId("task-id");
    task.setSignatureType(SignatureType.XML);
    task.setAdESType(AdESType.BES);
    task.setAdESObject(new DefaultAdESObject(null, null));
    task.setProcessingRulesUri("http://rules.example.com");
    task.setTbsData("tbs".getBytes());
    task.setSignature("signature".getBytes());
    task.setSignatureAlgorithmUri("http://alg.example.com");

    Assertions.assertEquals("task-id", task.getTaskId());
    Assertions.assertEquals(SignatureType.XML, task.getSignatureType());
    Assertions.assertEquals(AdESType.BES, task.getAdESType());
    Assertions.assertNotNull(task.getAdESObject());
    Assertions.assertEquals("http://rules.example.com", task.getProcessingRulesUri());
    Assertions.assertArrayEquals("tbs".getBytes(), task.getTbsData());
    Assertions.assertArrayEquals("signature".getBytes(), task.getSignature());
    Assertions.assertEquals("http://alg.example.com", task.getSignatureAlgorithmUri());
    Assertions.assertNotNull(task.toString());
  }

  @Test
  public void testEmptyByteArrays() {
    DefaultSignatureTask task = new DefaultSignatureTask();
    task.setTbsData(null);
    task.setSignature(null);
    Assertions.assertNull(task.getTbsData());
    Assertions.assertNull(task.getSignature());
    Assertions.assertNotNull(task.toString());
  }

  @Test
  public void testSetAdesType() {
    DefaultSignatureTask task = new DefaultSignatureTask();
    task.setAdESType("None");
    Assertions.assertNull(task.getAdESType());

    task = new DefaultSignatureTask();
    task.setAdESType((String) null);
    Assertions.assertNull(task.getAdESType());

    task = new DefaultSignatureTask();
    task.setAdESType("BES");
    Assertions.assertEquals(AdESType.BES, task.getAdESType());

    DefaultSignatureTask task2 = new DefaultSignatureTask();
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      task2.setAdESType("not-valid");
    });
  }

  @Test
  public void setSetSignatureType() {
    DefaultSignatureTask task = new DefaultSignatureTask();
    task.setSignatureType((String) null);
    Assertions.assertNull(task.getSignatureType());

    task = new DefaultSignatureTask();
    task.setSignatureType("XML");
    Assertions.assertEquals(SignatureType.XML, task.getSignatureType());

    DefaultSignatureTask task2 = new DefaultSignatureTask();
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      task2.setSignatureType("type");
    });
  }

}
