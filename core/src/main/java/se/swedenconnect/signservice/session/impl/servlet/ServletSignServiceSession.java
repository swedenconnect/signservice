package se.swedenconnect.signservice.session.impl.servlet;

import se.swedenconnect.signservice.session.SignServiceContext;
import se.swedenconnect.signservice.session.SignServiceSession;

import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

/**
 * {@link SignServiceSession} implementation where sessions are backed by
 * underlying {@link HttpSession} objects.
 *
 * @author magnus.hoflin@digg.se
 */
class ServletSignServiceSession implements SignServiceSession {

    private final HttpSession inner;

    /**
     * Private constructor.
     *
     * @param httpSession The underlying session object. Must not be null.
     * @throws NullPointerException in case {@code httpSession} is null.
     */
    ServletSignServiceSession(HttpSession httpSession) {
        if (httpSession == null) throw new NullPointerException("httpSession cannot be null.");
        inner = httpSession;
    }

    @Override
    public String getId() {
        return inner.getId();
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T extends Serializable> T getAttribute(final String name) throws IllegalStateException, ClassCastException {
        return (T) inner.getAttribute(name);
    }

    @Override
    public <T extends Serializable> T getAttribute(final String name, final Class<T> type) throws IllegalStateException, ClassCastException {
        return type.cast(inner.getAttribute(name));
    }

    @Override
    public SignServiceContext getSignServiceContext() throws IllegalStateException {
        return (SignServiceContext) inner.getAttribute(CONTEXT_NAME);
    }

    @Override
    public void setSignServiceContext(final SignServiceContext context) throws IllegalStateException {
        inner.setAttribute(CONTEXT_NAME, context);
    }

    @Override
    public List<String> getAttributeNames() throws IllegalStateException {
        return Collections.list(inner.getAttributeNames());
    }

    @Override
    public <T extends Serializable> void setAttribute(final String name, final T attribute) throws IllegalStateException {
        inner.setAttribute(name, attribute);
    }

    @Override
    public void removeAttribute(final String name) throws IllegalStateException {
        inner.removeAttribute(name);
    }

    @Override
    public void invalidate() {
        inner.invalidate();
    }

    @Override
    public Instant getCreationTime() throws IllegalStateException {
        return Instant.ofEpochMilli(inner.getCreationTime());
    }

    @Override
    public Instant getLastAccessedTime() throws IllegalStateException {
        return Instant.ofEpochMilli(inner.getLastAccessedTime());
    }
}
