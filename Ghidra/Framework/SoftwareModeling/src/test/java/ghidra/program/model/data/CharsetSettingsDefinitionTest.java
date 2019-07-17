/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.program.model.data;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.docking.settings.Settings;

public class CharsetSettingsDefinitionTest extends AbstractGenericTest {

	@Before
	public void setUp() {
		Map<Long, List<String>> encodingMappings = new HashMap<>();
		encodingMappings.put(0L, Arrays.asList("charset_0_0", "charset_0_1", "charset_0_2"));
		encodingMappings.put(1L, Arrays.asList("charset_1_0", "charset_1_1", "charset_1_2"));
		CharsetSettingsDefinition.setStaticEncodingMappingValues(encodingMappings);
	}

	@Test
	public void testDeprecatedEncoding() {
		Settings s = new SettingsBuilder();
		s.setLong("language", 1);
		s.setLong("encoding", 2);

		String cs = CharsetSettingsDefinition.CHARSET.getCharset(s, null);
		assertEquals("charset_1_2", cs);
	}

	@Test
	public void testDeprecatedEncoding_OutOfRangeLanguageId() {
		Settings s = new SettingsBuilder();
		s.setLong("language", 5);
		s.setLong("encoding", 2);

		String cs = CharsetSettingsDefinition.CHARSET.getCharset(s, null);
		assertNull(cs);

		s.setLong("language", -1);
		cs = CharsetSettingsDefinition.CHARSET.getCharset(s, null);
		assertNull(cs);
	}

	@Test
	public void testDeprecatedEncoding_OutOfRangeEncodingId() {
		Settings s = new SettingsBuilder();
		s.setLong("language", 1);
		s.setLong("encoding", 20);

		String cs = CharsetSettingsDefinition.CHARSET.getCharset(s, null);
		assertNull(cs);

		s.setLong("encoding", -1);
		cs = CharsetSettingsDefinition.CHARSET.getCharset(s, null);
		assertNull(cs);
	}

	@Test
	public void testCharset() {
		Settings s = new SettingsBuilder();
		s.setString("charset", "expected_charset_value");

		String cs = CharsetSettingsDefinition.CHARSET.getCharset(s, null);
		assertEquals("expected_charset_value", cs);
	}

	@Test
	public void testCharsetAndDeprecated() {
		// Should ignore the deprecated values in favor of the plain charset value
		Settings s = new SettingsBuilder();
		s.setString("charset", "expected_charset_value");
		s.setLong("language", 1);
		s.setLong("encoding", 2);

		String cs = CharsetSettingsDefinition.CHARSET.getCharset(s, null);
		assertEquals("expected_charset_value", cs);
	}

}
