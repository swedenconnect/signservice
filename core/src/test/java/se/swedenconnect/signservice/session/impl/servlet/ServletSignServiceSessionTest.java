/*
 * Copyright 2022 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package se.swedenconnect.signservice.session.impl.servlet;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import se.swedenconnect.signservice.session.SignServiceContext;
import se.swedenconnect.signservice.session.SignServiceSession;

import javax.servlet.http.HttpSession;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.mockito.Mockito.*;

/**
 * Test class for {@link ServletSignServiceSession}.
 *
 * @author magnus.hoflin@digg.se
 */
class ServletSignServiceSessionTest {

    HttpSession hSession;
    SignServiceSession session;

    @BeforeEach
    void init() {
        hSession = mockHttpSession();
        session = new ServletSignServiceSession(hSession);
    }

    @Test
    void getId() {
        Assertions.assertEquals("1234", session.getId());
    }

    @Test
    void getAttribute() {
        Assertions.assertEquals("value1", session.getAttribute("name1"));
        Assertions.assertEquals("value2", session.getAttribute("name2"));
        Assertions.assertNull(session.getAttribute("name3"));
    }

    @Test
    void getAttributeWithType() {
        Assertions.assertEquals("value1", session.getAttribute("name1", String.class));
    }

    @Test
    void getSignServiceContext() {
        Assertions.assertInstanceOf(SignServiceContext.class, session.getSignServiceContext());
    }

    @Test
    void setSignServiceContext() {
        SignServiceContext ssc = mock(SignServiceContext.class);
        session.setSignServiceContext(ssc);
        verify(hSession).setAttribute(SignServiceSession.CONTEXT_NAME, ssc);
    }

    @Test
    void getAttributeNames() {
        List<String> attributeNames = session.getAttributeNames();
        Assertions.assertTrue(attributeNames.contains("name1"));
        Assertions.assertTrue(attributeNames.contains("name2"));
        Assertions.assertFalse(attributeNames.contains("name3"));
    }

    @Test
    void setAttribute() {
        session.setAttribute("name1", "value1");
        verify(hSession).setAttribute("name1", "value1");
    }

    @Test
    void removeAttribute() {
        session.removeAttribute("name1");
        verify(hSession).removeAttribute("name1");
    }

    @Test
    void invalidate() {
        session.invalidate();
        verify(hSession).invalidate();
    }

    @Test
    void getCreationTime() {
        Assertions.assertInstanceOf(Instant.class, session.getCreationTime());
    }

    @Test
    void getLastAccessedTime() {
        Assertions.assertInstanceOf(Instant.class, session.getLastAccessedTime());
    }

    private HttpSession mockHttpSession() {
        HttpSession httpSession = mock(HttpSession.class);
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