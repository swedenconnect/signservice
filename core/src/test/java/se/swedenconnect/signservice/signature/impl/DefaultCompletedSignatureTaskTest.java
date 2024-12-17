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
package se.swedenconnect.signservice.signature.impl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.signature.AdESType;
import se.swedenconnect.signservice.signature.SignatureType;

/**
 * Test cases for DefaultCompletedSignatureTask.
 */
public class DefaultCompletedSignatureTaskTest {

  @Test
  public void testUsage() {
    DefaultRequestedSignatureTask rtask = new DefaultRequestedSignatureTask();

    rtask.setTaskId("task-id");
    rtask.setSignatureType(SignatureType.XML);
    rtask.setAdESType(AdESType.BES);
    rtask.setAdESObject(new DefaultAdESObject(null, null));
    rtask.setProcessingRulesUri("http://rules.example.com");
    rtask.setTbsData("tbs".getBytes());

    DefaultCompletedSignatureTask task = new DefaultCompletedSignatureTask(rtask);

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
  public void testEmptyByteArray() {
    DefaultCompletedSignatureTask task = new DefaultCompletedSignatureTask();
    task.setSignature(null);
    Assertions.assertNull(task.getSignature());
    Assertions.assertNotNull(task.toString());
  }
}
