/*
 * Copyright 2022 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
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
