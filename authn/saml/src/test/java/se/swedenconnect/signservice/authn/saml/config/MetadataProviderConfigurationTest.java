/*
 * Copyright 2022-2025 Sweden Connect
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
package se.swedenconnect.signservice.authn.saml.config;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

import se.swedenconnect.signservice.authn.saml.OpenSamlTestBase;

/**
 * Test cases for MetadataProviderConfiguration.
 */
public class MetadataProviderConfigurationTest extends OpenSamlTestBase {

//  private static final String backupFile = "target/test/saml/foo/backup.xml";
//
//  private static final String backupDir = "target/test2/saml/bar/backups";

  @BeforeAll
  public static void init() throws IOException {
    final File test = new File("target/test");
    if (test.exists()) {
      FileUtils.deleteDirectory(test);
    }
    final File test2 = new File("target/test2");
    if (test2.exists()) {
      FileUtils.deleteDirectory(test2);
    }
  }

  @AfterAll
  public static void destroy() throws IOException {
    final File test = new File("target/test");
    if (test.exists()) {
      FileUtils.deleteDirectory(test);
    }
    final File test2 = new File("target/test2");
    if (test2.exists()) {
      FileUtils.deleteDirectory(test2);
    }
  }

//  @Test
//  public void testHttp() {
//    final MetadataProviderConfiguration conf = new MetadataProviderConfiguration();
//    conf.setUrl("https://md.swedenconnect.se/role/idp.xml");
//    conf.setBackupLocation(backupFile);
//    final MetadataProvider provider = conf.create();
//    Assertions.assertNotNull(provider);
//    final File b = new File(backupFile);
//    Assertions.assertTrue(b.exists());
//  }
//
//  @Test
//  public void testMdq() {
//    final MetadataProviderConfiguration conf = new MetadataProviderConfiguration();
//    conf.setUrl("https://md.nordu.net");
//    conf.setBackupLocation(backupDir);
//    conf.setMdq(true);
//    final MetadataProvider provider = conf.create();
//    Assertions.assertNotNull(provider);
//    final File b = new File(backupDir);
//    Assertions.assertTrue(b.exists());
//  }
}
