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
package ghidra.feature.vt.api.util;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class StringableTest {

	@Test
	public void testCommentEncodingRoundTrip() {
		assertRoundTrip("C:\\Windows\\System32");
		assertRoundTrip("path\\to\\file");
		assertRoundTrip("ends with \\");
		assertRoundTrip("tab\tcr\rlf\nff\f");
		assertRoundTrip("plain");
		assertRoundTrip("\\t is not a tab");
	}

	@Test
	public void testDecodeTrailingBackslash() {
		assertEquals("ends with \\", Stringable.decodeString("ends with \\"));
	}

	@Test
	public void testDecodeUnknownEscapePreserved() {
		assertEquals("\\q", Stringable.decodeString("\\q"));
	}

	private void assertRoundTrip(String comment) {
		assertEquals(comment, Stringable.decodeString(Stringable.encodeString(comment)));
	}
}
