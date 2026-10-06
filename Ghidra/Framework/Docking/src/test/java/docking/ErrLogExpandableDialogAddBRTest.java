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
package docking;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Tests the string-building helper {@link ErrLogExpandableDialog#addBR(String)} in isolation,
 * without requiring a Swing display environment.  The helper is the single point where plain-text
 * error messages are converted into HTML-fragment form before being inserted into an HTML body
 * element; verifying it here ensures the fix for angle-bracket dropping (GitHub issue #1322)
 * is correct without needing a headless GUI test harness.
 */
public class ErrLogExpandableDialogAddBRTest {

	@Test
	public void testAngleBracketIsEscaped() {
		String result = ErrLogExpandableDialog.addBR("a < b");
		assertTrue("'<' must be escaped to '&lt;' so it is not interpreted as an HTML tag",
			result.contains("&lt;"));
		assertFalse("raw '<' must not appear in HTML output", result.contains("< b"));
	}

	@Test
	public void testTextAfterAngleBracketIsPreserved() {
		String result = ErrLogExpandableDialog.addBR("value < threshold: abort");
		assertTrue("text after '<' must not be swallowed", result.contains("threshold"));
		assertTrue("text before '<' must be preserved", result.contains("value"));
	}

	@Test
	public void testAmpersandIsEscaped() {
		String result = ErrLogExpandableDialog.addBR("foo & bar");
		assertTrue("'&' must be escaped to '&amp;'", result.contains("&amp;"));
	}

	@Test
	public void testGreaterThanIsEscaped() {
		String result = ErrLogExpandableDialog.addBR("a > b");
		assertTrue("'>' must be escaped to '&gt;'", result.contains("&gt;"));
	}

	@Test
	public void testNewlinesConvertedToBreakTags() {
		String result = ErrLogExpandableDialog.addBR("line1\nline2");
		assertTrue("newline must be converted to a <BR> tag", result.toLowerCase().contains("<br>"));
		assertTrue("first line content must be present", result.contains("line1"));
		assertTrue("second line content must be present", result.contains("line2"));
	}

	@Test
	public void testPlainTextWithNoSpecialCharsUnchanged() {
		String result = ErrLogExpandableDialog.addBR("simple message");
		assertTrue("plain text must pass through intact", result.contains("simple message"));
	}

	@Test
	public void testHtmlTagsInPlainTextAreEscaped() {
		// addBR is only invoked for non-HTML messages (getHTML handles <html>-prefixed
		// messages separately), so if an angle-bracket tag appears in plain text it must
		// be treated as literal characters, not markup.
		String result = ErrLogExpandableDialog.addBR("<b>bold?</b>");
		assertFalse("HTML tag must not be rendered as markup", result.contains("<b>"));
		assertTrue("escaped opening tag must appear", result.contains("&lt;b&gt;"));
	}
}
