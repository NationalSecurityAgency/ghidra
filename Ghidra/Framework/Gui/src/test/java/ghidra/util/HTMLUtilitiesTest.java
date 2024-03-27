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
package ghidra.util;

import static ghidra.util.HTMLUtilities.*;
import static org.junit.Assert.*;

import java.awt.Color;

import org.junit.Before;
import org.junit.Test;

public class HTMLUtilitiesTest {

	private SpyErrorLogger spyLogger = new SpyErrorLogger();

	@Before
	public void setUp() {
		Msg.setErrorLogger(spyLogger);
	}

	@Test
	public void testToHTML_WithoutNewlines() {
		String s = "This is the text to be converted";
		String html = HTMLUtilities.toHTML(s);
		assertEquals(HTML + s, html);
	}

	@Test
	public void testToHTML_WithNewlinesOnly() {
		String s = "This text has\na newline character";
		String html = HTMLUtilities.toHTML(s);
		assertEquals(HTML + "This text has<br>\na newline character", html);
	}

	@Test
	public void testToHTML_WithBrTagsOnly() {
		String s = "This text has<br>an existing BR tag";
		String html = HTMLUtilities.toHTML(s);
		assertEquals(HTML + s, html);
		spyLogger.assertLogMessage("cannot", "wrap");
	}

	@Test
	public void testToHTML_WithNewlinesAndBrTags() {
		String s = "This text has<br>\nan existing BR tag and a newline";
		String html = HTMLUtilities.toHTML(s);
		assertEquals(HTML + s, html);
		spyLogger.assertLogMessage("cannot", "wrap");
	}

	@Test
	public void testToWrappedHTML_DefaultWrapLimit() {
		String s =
			"This is a line that is longer than the default line limit of seventy-five characters";
		String html = HTMLUtilities.toWrappedHTML(s);
		assertEquals(HTML +
			"This is a line that is longer than the default line limit of seventy-five<br>\n" +
			"characters", html);
	}

	@Test
	public void testToWrappedHTML_MultipleNewlines_NoLimit() {
		// note: toWrappedHTML preserves whitespace
		String s = "Wrap\n\nhere\n\n\n";
		String html = HTMLUtilities.toWrappedHTML(s, 0);
		assertEquals(HTML + "Wrap<br>\n<br>\nhere<br>\n<br>\n<br>\n", html);
	}

	@Test
	public void testToWrappedHTML_SpecifiedWrapLimit() {
		String s = "Wrap here";
		String html = HTMLUtilities.toWrappedHTML(s, 4);
		assertEquals(HTML + "Wrap<br>\nhere", html);
	}

	@Test
	public void testToWrappedHTML_NoWrapLimit() {
		String s =
			"This is a line that is longer than the default line limit of seventy-five characters";
		String html = HTMLUtilities.toWrappedHTML(s, 0);
		assertEquals(HTML + s, html);
	}

	@Test
	public void testToLiteralHTML() {
		String s = "I have <b>some <i>markup</i></b>.";
		String html = HTMLUtilities.toLiteralHTML(s, 0);

		assertEquals(
			HTML + "I&nbsp;have&nbsp;&lt;b&gt;some&nbsp;&lt;i&gt;markup&lt;/i&gt;&lt;/b&gt;.",
			html);
	}

	@Test
	public void testToLiteralHTML_AlreadyStartingWithHTML() {
		String s = "<html>Wrap<br>here";
		String html = HTMLUtilities.toLiteralHTML(s, 4);
		assertEquals(HTML + "&lt;htm<br>\nl&gt;Wr<br>\nap&lt;b<br>\nr&gt;he<br>\nre", html);
	}

	@Test
	public void testToLiteralHTML_NoExisingHTML_SpecifiedLimit() {
		String s = "Wrap here";
		String html = HTMLUtilities.toLiteralHTML(s, 4);
		assertEquals(HTML + "Wrap<br>\n&nbsp;<br>\nhere", html);
	}

	@Test
	public void testFromHTML() {
		String s = "<html><b>Bold</b>, <i>italics</i>, <font size='3'>sized font!</font>";
		String text = Swing.runNow(() -> HTMLUtilities.fromHTML(s));
		assertEquals("Bold, italics, sized font!", text);
	}

	@Test
	public void testToRGBString() {
		String rgb = HTMLUtilities.toRGBString(Color.RED);
		assertEquals("255000000", rgb);
	}

	@Test
	public void testToHexString() {
		String rgb = HTMLUtilities.toHexString(Color.RED);
		assertEquals("#FF0000", rgb);
	}

	@Test
	public void testLinkPlaceholder() {
		String placeholderStr =
			HTMLUtilities.wrapWithLinkPlaceholder("Stuff inside link tag", "targetstr");
		String htmlStr = HTMLUtilities.convertLinkPlaceholdersToHyperlinks(placeholderStr);
		assertEquals("<a href=\"targetstr\">Stuff inside link tag</a>", htmlStr);
	}

	@Test
	public void testLinkPlaceholder_Regex_backrefs() {
		String placeholderStr =
			HTMLUtilities.wrapWithLinkPlaceholder("Stuff inside link tag", "test$1");
		String htmlStr = HTMLUtilities.convertLinkPlaceholdersToHyperlinks(placeholderStr);
		assertEquals("<a href=\"test$1\">Stuff inside link tag</a>", htmlStr);
	}

	@Test
	public void testLinkPlaceholder_htmlchars() {
		String placeholderStr =
			HTMLUtilities.wrapWithLinkPlaceholder("Stuff inside <b>link</b> tag", "test");
		String htmlStr = HTMLUtilities.convertLinkPlaceholdersToHyperlinks(placeholderStr);
		assertEquals("<a href=\"test\">Stuff inside <b>link</b> tag</a>", htmlStr);
	}

	@Test
	public void testEscapeHTML() {
		assertEquals("abc", HTMLUtilities.escapeHTML("abc"));
		assertEquals("&#x2222;", HTMLUtilities.escapeHTML("\u2222"));

		// unicode char above 0xffff encoded with 2 utf-16 characters
		assertEquals("&#x1F344;", HTMLUtilities.escapeHTML("\uD83C\uDF44"));

		assertEquals("&lt;abc&gt;", HTMLUtilities.escapeHTML("<abc>"));
		assertEquals("a&amp;b", HTMLUtilities.escapeHTML("a&b"));

	}
}
