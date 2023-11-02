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

import java.io.IOException;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import jakarta.annotation.Nonnull;

/**
 * Custom JSON deserializer for {@link DefaultHttpResponseAction}.
 */
public class DefaultHttpResponseActionDeserializer extends StdDeserializer<DefaultHttpResponseAction> {

  /** For serializing. */
  private static final long serialVersionUID = -3630787013978872401L;

  /** The object mapper used. */
  private final static ObjectMapper objectMapper = new ObjectMapper();

  /**
   * Default constructor.
   */
  public DefaultHttpResponseActionDeserializer() {
    super((Class<?>) null);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public DefaultHttpResponseAction deserialize(@Nonnull final JsonParser p, @Nonnull final DeserializationContext ctxt)
      throws IOException, JacksonException {

    final JsonNode node = p.getCodec().readTree(p);
    {
      final JsonNode post = node.get("post");
      if (post != null && !post.isNull() && post.isObject()) {
        return new DefaultHttpResponseAction(objectMapper.treeToValue(post, HttpPostAction.class));
      }
    }
    {
      final JsonNode redirect = node.get("redirect");
      if (redirect != null && !redirect.isNull() && redirect.isObject()) {
        return new DefaultHttpResponseAction(objectMapper.treeToValue(redirect, HttpRedirectAction.class));
      }
    }
    {
      final JsonNode body = node.get("body");
      if (body != null && !body.isNull() && body.isObject()) {
        return new DefaultHttpResponseAction(objectMapper.treeToValue(body, HttpBodyAction.class));
      }
    }
    throw new CustomJsonException("Could not deserialize HttpResponseAction");
  }

  /**
   * Exception class for our custom code.
   */
  private static final class CustomJsonException extends JsonProcessingException {

    private static final long serialVersionUID = 5518198073198081521L;

    /**
     * Constructor.
     *
     * @param msg error message
     */
    public CustomJsonException(@Nonnull final String msg) {
      super(msg);
    }

  }

}
