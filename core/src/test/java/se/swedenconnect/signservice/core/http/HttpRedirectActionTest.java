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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test cases for HttpRedirectAction and DefaultHttpRedirectAction.
 */
public class HttpRedirectActionTest {

  @Test
  public void testUsage() {
    final DefaultHttpRedirectAction action = new DefaultHttpRedirectAction("https://www.example.com?a=b&c=100");
    Assertions.assertEquals("https://www.example.com?a=b&c=100", action.getUrl());
    Assertions.assertEquals("redirect[url='https://www.example.com?a=b&c=100']", action.toString());
  }

  @Test
  public void testBuilder() {
    final HttpRedirectAction action = DefaultHttpRedirectAction.builder()
        .url("https://www.example.com")
        .parameter("a", "b")
        .parameter("c", "100")
        .build();
    Assertions.assertEquals("https://www.example.com?a=b&c=100", action.getUrl());
    Assertions.assertEquals("redirect[url='https://www.example.com?a=b&c=100']", action.toString());

    final HttpRedirectAction action2 = DefaultHttpRedirectAction.builder()
        .url("https://www.example.com?a=b&c=100")
        .build();
    Assertions.assertEquals("https://www.example.com?a=b&c=100", action2.getUrl());
    Assertions.assertEquals("redirect[url='https://www.example.com?a=b&c=100']", action2.toString());

    assertThatThrownBy(() -> {
      DefaultHttpRedirectAction.builder().build();
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("No URL assigned");

    assertThatThrownBy(() -> {
      DefaultHttpRedirectAction.builder().url("--NOT-A-URL").build();
    }).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void jsonSerializeDeserialize() throws Exception {
    final HttpRedirectAction action = DefaultHttpRedirectAction.builder()
        .url("https://www.example.com")
        .parameter("a", "b")
        .parameter("c", "100")
        .build();

    final ObjectMapper objectMapper = new ObjectMapper();
    final String json = objectMapper.writeValueAsString(action);

    final HttpRedirectAction action2 = objectMapper.readValue(json, HttpRedirectAction.class);

    Assertions.assertEquals(action.getUrl(), action2.getUrl());
  }

}
