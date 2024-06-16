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
package generic.theme;

import static org.junit.Assert.*;

import java.text.ParseException;
import java.util.List;

import org.junit.Test;

public class ThemeValueUtilsTest {
	@Test
	public void testParseGroupings() throws ParseException {
		String source = "(ab (cd))(ef)(( gh))";
		List<String> results = ThemeValueUtils.parseGroupings(source, '(', ')');
		assertEquals(3, results.size());
		assertEquals("ab (cd)", results.get(0));
		assertEquals("ef", results.get(1));
		assertEquals("( gh)", results.get(2));
	}

	@Test
	public void testParseGroupingsParseError() {
		String source = "(ab (cd))(ef)( gh))";
		try {
			ThemeValueUtils.parseGroupings(source, '(', ')');
			fail("Expected parse Exception");
		}
		catch (ParseException e) {
			//expected
		}
	}

	@Test
	public void testParseGroupingsParseError2() {
		String source = "  xx";
		try {
			ThemeValueUtils.parseGroupings(source, '(', ')');
			fail("Expected parse Exception");
		}
		catch (ParseException e) {
			// expected
		}
	}

}
