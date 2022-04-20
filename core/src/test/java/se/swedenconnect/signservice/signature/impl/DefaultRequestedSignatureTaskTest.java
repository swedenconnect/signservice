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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.signature.AdESType;
import se.swedenconnect.signservice.signature.SignatureType;

/**
 * Test cases for DefaultRequestedSignatureTask.
 */
public class DefaultRequestedSignatureTaskTest {

  @Test
  public void testUsage() {
    DefaultRequestedSignatureTask task = new DefaultRequestedSignatureTask();

    task.setTaskId("task-id");
    task.setSignatureType(SignatureType.XML);
    task.setAdESType(AdESType.BES);
    task.setAdESObject(new DefaultAdESObject(null, null));
    task.setProcessingRulesUri("http://rules.example.com");
    task.setTbsData("tbs".getBytes());

    Assertions.assertEquals("task-id", task.getTaskId());
    Assertions.assertEquals(SignatureType.XML, task.getSignatureType());
    Assertions.assertEquals(AdESType.BES, task.getAdESType());
    Assertions.assertNotNull(task.getAdESObject());
    Assertions.assertEquals("http://rules.example.com", task.getProcessingRulesUri());
    Assertions.assertArrayEquals("tbs".getBytes(), task.getTbsData());
    Assertions.assertNotNull(task.toString());
  }

  @Test
  public void testEmptyByteArray() {
    DefaultRequestedSignatureTask task = new DefaultRequestedSignatureTask();
    task.setTbsData(null);
    Assertions.assertNull(task.getTbsData());
    Assertions.assertNotNull(task.toString());
  }

  @Test
  public void testSetAdesType() {
    DefaultRequestedSignatureTask task = new DefaultRequestedSignatureTask();
    task.setAdESType("None");
    Assertions.assertNull(task.getAdESType());

    task = new DefaultRequestedSignatureTask();
    task.setAdESType((String) null);
    Assertions.assertNull(task.getAdESType());

    task = new DefaultRequestedSignatureTask();
    task.setAdESType("BES");
    Assertions.assertEquals(AdESType.BES, task.getAdESType());

    DefaultRequestedSignatureTask task2 = new DefaultRequestedSignatureTask();
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      task2.setAdESType("not-valid");
    });
  }

  @Test
  public void setSetSignatureType() {
    DefaultRequestedSignatureTask task = new DefaultRequestedSignatureTask();
    task.setSignatureType((String) null);
    Assertions.assertNull(task.getSignatureType());

    task = new DefaultRequestedSignatureTask();
    task.setSignatureType("XML");
    Assertions.assertEquals(SignatureType.XML, task.getSignatureType());

    DefaultRequestedSignatureTask task2 = new DefaultRequestedSignatureTask();
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      task2.setSignatureType("type");
    });
  }

}
