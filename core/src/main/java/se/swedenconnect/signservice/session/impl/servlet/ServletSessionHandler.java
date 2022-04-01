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

import se.swedenconnect.signservice.session.SessionHandler;
import se.swedenconnect.signservice.session.SessionMaintainer;
import se.swedenconnect.signservice.session.SignServiceSession;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Implementation of a {@link SessionHandler} for creating sessions given a {@link HttpServletRequest}.
 * Sessions created this way are backed by {@link HttpSession} objects.
 *
 * @author magnus.hoflin@digg.se
 */
public class ServletSessionHandler implements SessionHandler {

    /**
     * Equivalent to {@code getSession(request, false)}.
     *
     * @see ServletSessionHandler#getSession(HttpServletRequest, boolean)
     */
    @Override
    public SignServiceSession getSession(final HttpServletRequest httpRequest) {
        return getSession(httpRequest, false);
    }

    /**
     * Creates a session given an {@link HttpServletRequest}.
     *
     * @param httpRequest The HTTP servlet request
     * @param create      whether to create a new session object if no session object exists
     * @return In case {@code create} is false, and there is no existing session, null is returned. All other cases
     * will return a session object.
     */
    @Override
    public SignServiceSession getSession(final HttpServletRequest httpRequest, final boolean create) {
        HttpSession httpSession = httpRequest.getSession(create);
        return (httpSession == null) ? null : new ServletSignServiceSession(httpSession);
    }

    /**
     * @throws UnsupportedOperationException Always
     */
    @Override
    public SignServiceSession getSession(final SessionMaintainer input) {
        throw new UnsupportedOperationException();
    }

    /**
     * @throws UnsupportedOperationException Always
     */
    @Override
    public SignServiceSession getSession(final SessionMaintainer input, final boolean create) {
        throw new UnsupportedOperationException();
    }
}
