/*
 * Copyright 2022-2023 Sweden Connect
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
package se.swedenconnect.signservice.core.http;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test cases for HttpBodyAction and DefaultHttpBodyAction.
 */
public class HttpBodyActionTest {

  @Test
  public void testUsage() {
    final DefaultHttpBodyAction action = new DefaultHttpBodyAction();
    Assertions.assertEquals("body[content-length='0', response-headers={}]", action.toString());
    action.setContents("data".getBytes());
    action.addHeader("H1", "V1");

    Assertions.assertArrayEquals("data".getBytes(), action.getContents());
    Assertions.assertEquals(Map.of("H1", "V1"), action.getHeaders());
    Assertions.assertEquals("body[content-length='4', response-headers={H1=V1}]", action.toString());

    action.removeHeader("H1");
    Assertions.assertTrue(action.getHeaders().isEmpty());
    Assertions.assertEquals("body[content-length='4', response-headers={}]", action.toString());

    action.setHeaders(Map.of("H1", "V1", "H2", "V2"));
    Assertions.assertArrayEquals("data".getBytes(), action.getContents());
    Assertions.assertEquals(Map.of("H1", "V1", "H2", "V2"), action.getHeaders());
    Assertions.assertEquals("body[content-length='4', response-headers={H1=V1, H2=V2}]", action.toString());
  }

  @Test
  public void testBuilder() {
    assertThatThrownBy(() -> {
      DefaultHttpBodyAction.builder().build();
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("No body contents assigned");

    final HttpBodyAction action = DefaultHttpBodyAction.builder()
        .contents("data".getBytes())
        .header("H1", "V1")
        .header("H2", "V2")
        .build();

    Assertions.assertArrayEquals("data".getBytes(), action.getContents());
    Assertions.assertEquals(Map.of("H1", "V1", "H2", "V2"), action.getHeaders());
    Assertions.assertEquals("body[content-length='4', response-headers={H1=V1, H2=V2}]", action.toString());
  }

  @Test
  public void jsonSerializeDeserialize() throws Exception {
    final HttpBodyAction action = DefaultHttpBodyAction.builder()
        .contents("data".getBytes())
        .header("H1", "V1")
        .header("H2", "V2")
        .build();

    final ObjectMapper objectMapper = new ObjectMapper();
    final String json = objectMapper.writeValueAsString(action);


    final HttpBodyAction action2 = objectMapper.readValue(json, HttpBodyAction.class);

    Assertions.assertArrayEquals(action.getContents(), action2.getContents());
    Assertions.assertEquals(action.getHeaders(), action2.getHeaders());
  }

}
