/*
 * MIT License
 *
 * Copyright 2022 Sweden Connect
 */
package se.swedenconnect.signservice.api.session;

import javax.servlet.http.HttpServletRequest;

/**
 * Marker interface for representing the input needed by the {@link SignServiceSessionHandler} to
 * get a session object. In most cases a {@link HttpServletRequest} is used, but when session
 * handling is not based on HTTP requests but other means we need a way of representing the input
 * passed to {@link SignServiceSessionHandler#getSession(SessionMaintainer)} and
 * {@link SignServiceSessionHandler#getSession(SessionMaintainer, boolean)}.
 */
public interface SessionMaintainer {
}
