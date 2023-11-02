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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test cases for HttpResponseAction and DefaultHttpResponseAction.
 */
public class HttpResponseActionTest {

  @Test
  public void testBody() throws Exception {
    final HttpBodyAction body = DefaultHttpBodyAction.builder()
        .contents("data".getBytes())
        .header("header", "value")
        .build();
    final HttpResponseAction action = new DefaultHttpResponseAction(body);

    Assertions.assertArrayEquals(body.getContents(), action.getBody().getContents());
    Assertions.assertEquals(body.getHeaders(), action.getBody().getHeaders());
    Assertions.assertEquals(body.toString(), action.toString());

    final ObjectMapper objectMapper = new ObjectMapper();
    final String json = objectMapper.writeValueAsString(action);

    final HttpResponseAction action2 = objectMapper.readValue(json, HttpResponseAction.class);

    Assertions.assertNull(action2.getPost());
    Assertions.assertNull(action2.getRedirect());
    Assertions.assertArrayEquals(body.getContents(), action2.getBody().getContents());
    Assertions.assertEquals(body.getHeaders(), action2.getBody().getHeaders());
    Assertions.assertEquals(body.toString(), action2.toString());
  }

  @Test
  public void testRedirect() throws Exception {
    final HttpRedirectAction redirect = DefaultHttpRedirectAction.builder()
        .url("https://www.example.com")
        .parameter("a", "b")
        .parameter("c", "100")
        .build();
    final HttpResponseAction action = new DefaultHttpResponseAction(redirect);

    final ObjectMapper objectMapper = new ObjectMapper();
    final String json = objectMapper.writeValueAsString(action);

    final HttpResponseAction action2 = objectMapper.readValue(json, HttpResponseAction.class);

    Assertions.assertNull(action2.getPost());
    Assertions.assertNull(action2.getBody());
    Assertions.assertEquals(redirect.getUrl(), action2.getRedirect().getUrl());
    Assertions.assertEquals(redirect.toString(), action2.toString());
  }

  @Test
  public void testPost() throws Exception {
    final HttpPostAction post = DefaultHttpPostAction.builder()
        .url("https://www.example.com/post")
        .parameter("P1", "V1")
        .parameter("P2", "V2")
        .build();

    final HttpResponseAction action = new DefaultHttpResponseAction(post);

    final ObjectMapper objectMapper = new ObjectMapper();
    final String json = objectMapper.writeValueAsString(action);

    final HttpResponseAction action2 = objectMapper.readValue(json, HttpResponseAction.class);

    Assertions.assertNull(action2.getRedirect());
    Assertions.assertNull(action2.getBody());
    Assertions.assertEquals(post.getUrl(), action2.getPost().getUrl());
    Assertions.assertEquals(post.getParameters(), action2.getPost().getParameters());
    Assertions.assertEquals(post.toString(), action2.toString());
  }

  @Test
  public void testDeserializationError() throws Exception {

    final ObjectMapper objectMapper = new ObjectMapper();

    final String json =
        "{\"post\":{\"badurl\":\"https://www.example.com/post\",\"parameters\":{\"P1\":\"V1\",\"P2\":\"V2\"}}}";

    assertThatThrownBy(() -> {
      objectMapper.readValue(json, HttpResponseAction.class);
    }).isInstanceOf(JsonProcessingException.class);

    final String json2 = "{\"kalle\": \"kula\" }";

    assertThatThrownBy(() -> {
      objectMapper.readValue(json2, HttpResponseAction.class);
    }).isInstanceOf(JsonProcessingException.class)
        .hasMessage("Could not deserialize HttpResponseAction");

  }

}
