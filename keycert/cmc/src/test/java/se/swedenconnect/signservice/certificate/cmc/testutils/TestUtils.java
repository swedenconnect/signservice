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
package se.swedenconnect.signservice.certificate.cmc.testutils;

import org.bouncycastle.util.encoders.Base64;

/**
 * Utilities for tests
 */
public class TestUtils {

  public static String base64Print(String base64Data){
    return base64Data == null ? "null" : base64Print(Base64.decode(base64Data),80);
  }
  public static String base64Print(byte[] base64Data){
    return base64Data == null ? "null" : base64Print(base64Data,80);
  }

  public static String base64Print(byte[] data, int width) {
    // Create a String with linebreaks
    String b64String = Base64.toBase64String(data).replaceAll("(.{" + width + "})", "$1\n");
    // Ident string with 6 spaces
    return b64String.replaceAll("(?m)^", "      ");
  }
}
