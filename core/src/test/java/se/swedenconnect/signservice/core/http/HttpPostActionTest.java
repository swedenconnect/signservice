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
package se.swedenconnect.signservice.core.http;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test cases for HttpPostAction and DefaultHttpPostAction.
 */
public class HttpPostActionTest {

  @Test
  public void testUsage() {
    final DefaultHttpPostAction action = new DefaultHttpPostAction("https://www.example.com/post");
    action.setParameters(Map.of("P1", "V1"));
    action.addParameter("P2", "V2");

    Assertions.assertEquals("https://www.example.com/post", action.getUrl());
    Assertions.assertEquals(Map.of("P1", "V1", "P2", "V2"), action.getParameters());
    Assertions.assertEquals("post[url='https://www.example.com/post', parameters={P1=V1, P2=V2}]", action.toString());
  }

  @Test
  public void testBuilder() {

    final HttpPostAction action = DefaultHttpPostAction.builder()
        .url("https://www.example.com/post")
        .parameter("P1", "V1")
        .parameter("P2", "V2")
        .build();

    Assertions.assertEquals("https://www.example.com/post", action.getUrl());
    Assertions.assertEquals(Map.of("P1", "V1", "P2", "V2"), action.getParameters());
    Assertions.assertEquals("post[url='https://www.example.com/post', parameters={P1=V1, P2=V2}]", action.toString());

    final HttpPostAction action2 = DefaultHttpPostAction.builder()
        .parameter("P1", "V1")
        .parameter("A", "B")
        .url("https://www.example.com/post")
        .parameter("P2", "V2")
        .build();

    Assertions.assertEquals("https://www.example.com/post", action2.getUrl());
    Assertions.assertEquals(Map.of("P1", "V1", "A", "B", "P2", "V2"), action2.getParameters());
    Assertions.assertEquals("post[url='https://www.example.com/post', parameters={P1=V1, A=B, P2=V2}]",
        action2.toString());

    assertThatThrownBy(() -> {
      DefaultHttpPostAction.builder().build();
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("No URL assigned");
  }

  @Test
  public void jsonSerializeDeserialize() throws Exception {
    final HttpPostAction action = DefaultHttpPostAction.builder()
        .url("https://www.example.com/post")
        .parameter("P1", "V1")
        .parameter("P2", "V2")
        .build();

    final ObjectMapper objectMapper = new ObjectMapper();
    final String json = objectMapper.writeValueAsString(action);

    final HttpPostAction action2 = objectMapper.readValue(json, HttpPostAction.class);

    Assertions.assertEquals(action.getUrl(), action2.getUrl());
    Assertions.assertEquals(action.getParameters(), action2.getParameters());
  }

}
