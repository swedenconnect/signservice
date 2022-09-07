/*
 * Copyright 2022 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.signservice.session.impl;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.session.SignServiceContext;
import se.swedenconnect.signservice.session.SignServiceSession;

/**
 * Test class for DefaultSignServiceSession.
 */
public class DefaultSignServiceSessionTest {

  HttpSession hSession;
  SignServiceSession session;

  @BeforeEach
  void init() {
    this.hSession = mockHttpSession();
    session = new DefaultSignServiceSession(this.hSession);
  }

  @Test
  void testGetId() {
    Assertions.assertEquals("1234", this.session.getId());
  }

  @Test
  void testGetAttribute() {
    Assertions.assertEquals("value1", this.session.getAttribute("name1"));
    Assertions.assertEquals("value2", this.session.getAttribute("name2"));
    Assertions.assertNull(this.session.getAttribute("name3"));
  }

  @Test
  void testGetAttributeWithType() {
    Assertions.assertEquals("value1", this.session.getAttribute("name1", String.class));
  }

  @Test
  void testGetSignServiceContext() {
    Assertions.assertInstanceOf(SignServiceContext.class, this.session.getSignServiceContext());
  }

  @Test
  void testSetSignServiceContext() {
    final SignServiceContext ssc = mock(SignServiceContext.class);
    this.session.setSignServiceContext(ssc);
    verify(this.hSession).setAttribute(SignServiceSession.CONTEXT_NAME, ssc);
  }

  @Test
  void testGetAttributeNames() {
    final List<String> attributeNames = this.session.getAttributeNames();
    Assertions.assertTrue(attributeNames.contains("name1"));
    Assertions.assertTrue(attributeNames.contains("name2"));
    Assertions.assertFalse(attributeNames.contains("name3"));
  }

  @Test
  void testSetAttribute() {
    this.session.setAttribute("name1", "value1");
    verify(this.hSession).setAttribute("name1", "value1");
  }

  @Test
  void testRemoveAttribute() {
    this.session.removeAttribute("name1");
    verify(this.hSession).removeAttribute("name1");
  }

  @Test
  void testInvalidate() {
    this.session.invalidate();
    verify(this.hSession).invalidate();
  }

  @Test
  void testGetCreationTime() {
    Assertions.assertInstanceOf(Instant.class, this.session.getCreationTime());
  }

  @Test
  void testGetLastAccessedTime() {
    Assertions.assertInstanceOf(Instant.class, this.session.getLastAccessedTime());
  }

  private HttpSession mockHttpSession() {
    final HttpSession httpSession = mock(HttpSession.class);
    when(httpSession.getId()).thenReturn("1234");
    when(httpSession.getAttribute("name1")).thenReturn("value1");
    when(httpSession.getAttribute("name2")).thenReturn("value2");
    when(httpSession.getAttributeNames()).thenReturn(Collections.enumeration(List.of("name1", "name2")));
    when(httpSession.getAttribute(SignServiceSession.CONTEXT_NAME)).thenReturn(mock(SignServiceContext.class));
    when(httpSession.getCreationTime()).thenReturn(Instant.now().getEpochSecond());
    when(httpSession.getLastAccessedTime()).thenReturn(Instant.now().getEpochSecond());
    return httpSession;
  }
}