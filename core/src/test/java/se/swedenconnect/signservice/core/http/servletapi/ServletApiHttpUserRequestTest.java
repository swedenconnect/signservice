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
package se.swedenconnect.signservice.core.http.servletapi;

import java.util.Collections;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * Test cases for ServletApiHttpUserRequest.
 */
public class ServletApiHttpUserRequestTest {

  @Test
  public void test() {
    final HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
    Mockito.when(httpServletRequest.getMethod()).thenReturn("GET");
    Mockito.when(httpServletRequest.getRequestURL()).thenReturn(
        new StringBuffer("https://www.example.com/ctx/path1/path2"));
    Mockito.when(httpServletRequest.getScheme()).thenReturn("https");
    Mockito.when(httpServletRequest.getServerPort()).thenReturn(443);
    Mockito.when(httpServletRequest.getServerName()).thenReturn("www.example.com");
    Mockito.when(httpServletRequest.getContextPath()).thenReturn("/ctx");
    Mockito.when(httpServletRequest.getServletPath()).thenReturn("/path1/path2");
    Mockito.when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");

    final Map<String, String[]> parameters = Map.ofEntries(
        Map.entry("p1", new String[] { "v1" }),
        Map.entry("p2", new String[] {}),
        Map.entry("p3", new String[] { "v3", "v33" }));
    Mockito.when(httpServletRequest.getParameterMap()).thenReturn(parameters);
    Mockito.when(httpServletRequest.getParameter(Mockito.anyString())).then(a -> {
      final String[] values = parameters.get(a.getArgument(0, String.class));
      if (values == null || values.length == 0) {
        return null;
      }
      return values[0];
      });

    final Map<String, String> headers = Map.of(
        "H1", "V1",
        "H2", "V2",
        "H3", "V3");
    Mockito.when(httpServletRequest.getHeader(Mockito.anyString())).then(a -> {
      return headers.get(a.getArgument(0, String.class));
    });
    Mockito.when(httpServletRequest.getHeaderNames()).thenReturn(Collections.enumeration(headers.keySet()));

    final ServletApiHttpUserRequest request = new ServletApiHttpUserRequest(httpServletRequest);
    Assertions.assertEquals("GET", request.getMethod());
    Assertions.assertEquals("https://www.example.com/ctx/path1/path2", request.getRequestUrl());
    Assertions.assertEquals("https://www.example.com/ctx", request.getServerBaseUrl());
    Assertions.assertEquals("/path1/path2", request.getServerServletPath());
    Assertions.assertEquals("127.0.0.1", request.getClientIpAddress());
    Assertions.assertEquals("v1", request.getParameter("p1"));
    Assertions.assertNull(request.getParameter("v2"));
    Assertions.assertEquals("v3", request.getParameter("p3"));
    final Map<String, String> pars = request.getParameters();
    Assertions.assertEquals(2, pars.size());
    Assertions.assertEquals("v1", pars.get("p1"));
    Assertions.assertEquals("v3", pars.get("p3"));
    Assertions.assertEquals("V1", request.getHeader("H1"));
    Assertions.assertNull(request.getHeader("H4"));
    Assertions.assertEquals(headers, request.getHeaders());
  }

}
