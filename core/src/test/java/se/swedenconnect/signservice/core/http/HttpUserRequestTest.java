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

import java.util.Map;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test cases for HttpUserRequest and DefaultHttpUserRequest.
 */
public class HttpUserRequestTest {

  @Test
  public void testUsage() throws Exception {

    final Map<String, String[]> parameters = Map.ofEntries(
        Map.entry("p1", new String[] { "v1" }),
        Map.entry("p3", new String[] { "v3", "v33" }));

    final Map<String, String[]> headers = Map.of(
        "H1", new String[] { "V1" },
        "H2", new String[] { "V2", "V22" },
        "H3", new String[] { "V3" });

    final DefaultHttpUserRequest request = new DefaultHttpUserRequest();
    request.setMethod("GET");
    request.setClientIpAddress("127.0.0.1");
    request.setRequestUrl("https://www.example.com/ctx/path1/path2");
    request.setServerBaseUrl("https://www.example.com/ctx");
    request.setServerServletPath("/path1/path2");
    request.setParameters(parameters);
    request.setHeaders(headers);

    Assertions.assertEquals("GET", request.getMethod());
    Assertions.assertEquals("https://www.example.com/ctx/path1/path2", request.getRequestUrl());
    Assertions.assertEquals("https://www.example.com/ctx", request.getServerBaseUrl());
    Assertions.assertEquals("/path1/path2", request.getServerServletPath());
    Assertions.assertEquals("127.0.0.1", request.getClientIpAddress());
    Assertions.assertEquals("v1", request.getParameter("p1"));
    Assertions.assertEquals("v3", request.getParameter("p3"));
    final Map<String, String[]> pars = request.getParameters();
    Assertions.assertEquals(2, pars.size());
    Assertions.assertArrayEquals(parameters.get("p1"), pars.get("p1"));
    Assertions.assertArrayEquals(parameters.get("p3"), pars.get("p3"));
    Assertions.assertEquals("V1", request.getHeader("H1"));
    Assertions.assertEquals("V2", request.getHeader("H2"));
    Assertions.assertNull(request.getHeader("H4"));
    final Map<String, String[]> h = request.getHeaders();
    Assertions.assertEquals(headers.size(), h.size());
    Assertions.assertArrayEquals(headers.get("H1"), h.get("H1"));
    Assertions.assertArrayEquals(headers.get("H2"), h.get("H2"));
    Assertions.assertArrayEquals(headers.get("H3"), h.get("H3"));

    // Make sure it is possible to serialize to JSON
    //
    final ObjectMapper objectMapper = new ObjectMapper();
    final String json = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(request);

    final HttpUserRequest request2 = objectMapper.readValue(json, HttpUserRequest.class);

    Assertions.assertEquals(request.getMethod(), request2.getMethod());
    Assertions.assertEquals(request.getRequestUrl(), request2.getRequestUrl());
    Assertions.assertEquals(request.getServerBaseUrl(), request2.getServerBaseUrl());
    Assertions.assertEquals(request.getServerServletPath(), request2.getServerServletPath());
    Assertions.assertEquals(request.getClientIpAddress(), request2.getClientIpAddress());
    Assertions.assertEquals("v1", request2.getParameter("p1"));
    Assertions.assertEquals("v3", request2.getParameter("p3"));
    final Map<String, String[]> pars2 = request2.getParameters();
    Assertions.assertEquals(2, pars2.size());
    Assertions.assertArrayEquals(parameters.get("p1"), pars2.get("p1"));
    Assertions.assertArrayEquals(parameters.get("p3"), pars2.get("p3"));
    Assertions.assertEquals("V1", request2.getHeader("H1"));
    Assertions.assertEquals("V2", request2.getHeader("H2"));
    Assertions.assertNull(request2.getHeader("H4"));
    final Map<String, String[]> h2 = request.getHeaders();
    Assertions.assertEquals(headers.size(), h2.size());
    Assertions.assertArrayEquals(headers.get("H1"), h2.get("H1"));
    Assertions.assertArrayEquals(headers.get("H2"), h2.get("H2"));
    Assertions.assertArrayEquals(headers.get("H3"), h2.get("H3"));
  }

}
