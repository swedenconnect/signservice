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
import org.junit.jupiter.api.Test;
import se.swedenconnect.signservice.session.SessionHandler;
import se.swedenconnect.signservice.session.SessionMaintainer;
import se.swedenconnect.signservice.session.SignServiceSession;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link ServletSessionHandler}.
 *
 * @author magnus.hoflin@digg.se
 */
class ServletSessionHandlerTest {

    @Test
    void getSession() {
        HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getSession(false)).thenReturn(mock(HttpSession.class));

        SessionHandler sh = new ServletSessionHandler();
        SignServiceSession session = sh.getSession(servletRequest);

        assertInstanceOf(ServletSignServiceSession.class, session);
    }

    @Test
    void getNullSession() {
        HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getSession(false)).thenReturn(null);

        SessionHandler sh = new ServletSessionHandler();
        SignServiceSession session = sh.getSession(servletRequest);

        assertNull(session);
    }

    @Test()
    void getSessionUnsupported() {
        SessionHandler sh = new ServletSessionHandler();
        SessionMaintainer maintainer = new SessionMaintainer() {
        };

        Assertions.assertThrows(UnsupportedOperationException.class, () -> sh.getSession(maintainer));
        Assertions.assertThrows(UnsupportedOperationException.class, () -> sh.getSession(maintainer, false));
    }
}