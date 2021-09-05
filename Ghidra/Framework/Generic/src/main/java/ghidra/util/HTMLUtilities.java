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

import java.awt.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JLabel;
import javax.swing.plaf.basic.BasicHTML;
import javax.swing.text.View;

import generic.text.TextLayoutGraphics;
import ghidra.util.html.HtmlLineSplitter;
import utilities.util.reflection.ReflectionUtilities;

/**
 * A helper class providing static methods for formatting text with common HTML tags.
 *
 * <P>Many clients use this class to render content as HTML.  Below are a few use cases along
 * with the method that should be used for each.
 * <TABLE BORDER="1"><caption></caption>
 * 		<TR>
 * 			<TH>Use Case</TH><TH>Function</TH><TH>Description</TH>
 * 		</TR>
 * 		<TR>
 * 			<TD>
 * 				A client wishes to display a simple text message (that itself contains no HTML
 * 				markup) as HTML.  The message may contain newline characters.
 * 			</TD>
 * 			<TD>
 * 				{@link #toHTML(String)}
 * 			</TD>
 * 			<TD>
 * 				The given text has all newline characters (\n) replaced with &lt;BR&gt; tags so
 * 				that the HTML display of the text will visually display multiple lines.  Also,
 * 				the final text is prepended with &lt;HTML&gt; so that the Java HTML rendering
 * 				engine will render the result as HTML.
 * 			</TD>
 * 		</TR>
 *  		<TR>
 * 			<TD>
 * 				A client wishes to display a simple text message (that itself may or may not
 * 				contain HTML markup) as HTML.  Further, the client wishes to not only split
 * 				lines at newline characters, but also wishes to ensure that no line is longer
 * 				than a specified limit.
 * 			</TD>
 * 			<TD>
 * 				{@link #toWrappedHTML(String)} or {@link #toWrappedHTML(String, int)}
 * 			</TD>
 * 			<TD>
 * 				This text works the same as {@link #toHTML(String)} with the addition of
 * 				line-wrapping text that passes the given cutoff.
 * 			</TD>
 * 		</TR>
 *  		<TR>
 * 			<TD>
 * 				A client wishes to display a text message with dynamic content, unknown at the
 * 				time of programming.
 * 			</TD>
 * 			<TD>
 * 				{@link #toLiteralHTML(String, int)}
 * 			</TD>
 * 			<TD>
 * 				This method works the same as {@link #toWrappedHTML(String)}, with the addition
 * 				of 'friendly encoding', or escaping, any embedded HTML content.  The effect of
 * 				this is that any existing HTML markup is not rendered as HTML, but is displayed
 * 				as plain text.
 * 			</TD>
 * 		</TR>
 *  		<TR>
 * 			<TD>
 * 				A client wishes to display, as a tooltip, a text message with
 * 				dynamic content, unknown at the time of programming.  Tooltips are unique from
 * 				general HTML in that we want them to share a common line wrapping length.
 * 			</TD>
 * 			<TD>
 * 				{@link #toLiteralHTMLForTooltip(String)}
 * 			</TD>
 * 			<TD>
 * 				This method works the same as {@link #toLiteralHTML(String, int)}, with the
 * 				addition of capping the max text length, as well as setting the line-wrap length
 * 				to {@link #DEFAULT_MAX_LINE_LENGTH}.
 * 			</TD>
 * 		</TR>
 *  		<TR>
 * 			<TD>
 * 				A client wishes to convert newlines in text into HTML line breaks, without adding
 * 				HTML tags around the text, which allows them to embed this text into a
 * 				larger HTML document.
 * 			</TD>
 * 			<TD>
 * 				{@link #lineWrapWithHTMLLineBreaks(String)} or
 * 				{@link #lineWrapWithHTMLLineBreaks(String, int)}
 * 			</TD>
 * 			<TD>
 * 				This first method will simply convert all newline characters to
 * 				&lt;BR&gt; tags.  The second method adds the ability to trigger line-wrapping
 * 				at the given length as well.
 * 			</TD>
 * 		</TR>
 * </TABLE>
 *
 */
public class HTMLUtilities {

	private static final int DEFAULT_MAX_LINE_LENGTH = 75;
	private static final int DEFAULT_TOOLTIP_MAX_LINE_LENGTH = 100;
	private static final int MAX_TOOLTIP_LENGTH = 2000; // arbitrary
	private static final int TAB_SIZE = 4;

	public static final String HTML = "<HTML>";
	public static final String HTML_CLOSE = "</HTML>";
	public static final String BR = "<BR>";
	public static final String PRE = "<PRE>";
	public static final String PRE_CLOSE = "</PRE>";

	/**
	 * A tag to mark code that could be made into a hyperlink.   This allows you to mark
	 * text for future linking, without rendering it as a hyperlink.
	 */
	private static final String LINK_PLACEHOLDER_CONTENT = "__CONTENT__";
	public static final String LINK_PLACEHOLDER_OPEN =
		"<!-- LINK " + LINK_PLACEHOLDER_CONTENT + " -->";
	public static final String LINK_PLACEHOLDER_CLOSE = "<!-- /LINK -->";

	public static String HTML_SPACE = "&nbsp;";
	public static String HTML_NEW_LINE = BR;

	public static final String MAROON = "#990000";
	public static final String GREEN = "#009900";
	public static final String BLUE = "#000099";
	public static final String PURPLE = "#990099";
	public static final String DARK_CYAN = "#009999";
	public static final String OLIVE = "#999900";
	public static final String ORANGE = "#FF9900";
	public static final String PINK = "#FF9999";
	public static final String YELLOW = "#FFFF00";
	public static final String GRAY = "#888888";

	/**
	 * Marks the given text as HTML in order to be rendered thusly by Java widgets.
	 *
	 * @param text the original text
	 * @return the text marked as HTML
	 */
	public static String wrapAsHTML(String text) {
		return HTML + fixupHTMLRenderingIssues(text);
	}

	private static String fixupHTMLRenderingIssues(String text) {
		if (text.startsWith("/")) {
			// Java's HTML rendering will not show the text if it starts with a forward slash...
			// not sure why...this escape seems to work
			text = HTML_SPACE + text;
		}
		return text;
	}

	/**
	 * Surrounds the indicated text with HTML font coloring tags so that the
	 * text will display in color within HTML.  The given color will be converted to its
	 * hex value.
	 *
	 * @param color The Java color object to use
	 * @param text the original text
	 * @return the string for HTML colored text
	 */
	public static String colorString(Color color, String text) {
		String rgb = toHexString(color);
		return "<FONT COLOR=\"" + rgb + "\">" + text + "</FONT>";
	}

	/**
	 * Surrounds the indicated text with HTML font coloring tags so that the
	 * text will display in color within HTML.
	 * @param rgbColor (eg. "#8c0000") a string indicating the RGB hexadecimal color
	 * @param text the original text
	 * @return the string for HTML colored text
	 */
	public static String colorString(String rgbColor, String text) {
		return "<FONT COLOR=\"" + rgbColor + "\">" + text + "</FONT>";
	}

	/**
	 * Surrounds the indicated numeric value with HTML font coloring tags so that the
	 * numeric value will display in color within HTML.
	 * @param rgbColor (eg. "#8c0000") a string indicating the RGB hexadecimal color
	 * @param value the numeric value to be converted to text and wrapped with color tags.
	 * @return the string for the HTML colored number
	 */
	public static String colorString(String rgbColor, int value) {
		return "<FONT COLOR=\"" + rgbColor + "\">" + value + "</FONT>";
	}

	/**
	 * Creates a string with the indicated number of HTML space characters (<code>&#x26;nbsp;</code>).
	 * @param num the number of HTML spaces
	 * @return the string o HTML spaces
	 */
	public static String spaces(int num) {
		StringBuilder buf = new StringBuilder(HTML_SPACE.length() * num);
		for (int i = 0; i < num; i++) {
			buf.append(HTML_SPACE);
		}
		return buf.toString();
	}

	/**
	 * Surrounds the specified text with the HTML begin and end tags for bold.
	 * @param text the original text
	 * @return the text with the bold HTML tags
	 */
	public static String bold(String text) {
		return "<b>" + text + "</b>";
	}

	/**
	 * Surrounds the specified text with the HTML begin and end tags for underlined text.
	 * @param text the original text
	 * @return the text with the underline HTML tags
	 */
	public static String underline(String text) {
		return "<u>" + text + "</u>";
	}

	/**
	 * Surrounds the specified text with the HTML begin and end tags for italic.
	 * @param text the original text
	 * @return the text with the italic HTML tags
	 */
	public static String italic(String text) {
		return "<i>" + text + "</i>";
	}

	/**
	 * Returns true if the given text is HTML.  For this to be true, the text must begin with
	 * the &lt;HTML&gt; tag.
	 *
	 * @param text the text to check
	 * @return true if the given text is HTML
	 */
	public static boolean isHTML(String text) {
		if (text == null) {
			return false;
		}

		String testText = text.trim();
		return BasicHTML.isHTMLString(testText);
	}

	/**
	 * Returns true if the text cannot be broken into lines due to
	 * the usage of particular HTML constructs.
	 *
	 * @param text the text to check
	 * @return true if the text cannot be correctly broken into lines
	 */
	public static boolean isUnbreakableHTML(String text) {
		if (text.contains(HTML_SPACE) && !text.contains(" ")) {
			// this can happen if the client has called a method on this class that turns spaces
			// to the HTML_SPACE
			return true;
		}

		if (text.contains(HTML_NEW_LINE)) {
			// this implies the client has already broken lines in their preferred location
			return true;
		}

		return false;
	}

	private static void logUnbreakableHTMLWarning() {
		//
		// When we wish to split text, we do so on '\n' characters and on spaces.  If the given
		// text does not have spaces, then we will break in the middle of a word, which may
		// happen to be HTML entities.  Breaking on these would produce bad output.
		//
		// This message will be output when a user calls a method to wrap lines that are already
		// marked as HTML or will be difficult to wrap without breaking an HTML construct.
		//
		Throwable t = ReflectionUtilities.createJavaFilteredThrowable();
		Msg.error(HTMLUtilities.class,
			"Cannot reliably wrap HTML; not changing text.  Update the call to this method", t);
	}

	/**
	 * Sets the font size of the given text by wrapping it in &lt;font&gt; tags.
	 *
	 * @param text the text to size
	 * @param ptSize the point size of the text
	 * @return the updated String
	 */
	public static String setFontSize(String text, int ptSize) {

		int start = 0;
		if (StringUtilities.startsWithIgnoreCase(text, HTML)) {
			start = HTML.length();
		}

		StringBuilder buffy = new StringBuilder(text);
		buffy.insert(start, "<SPAN STYLE=\"font-size: " + ptSize + "pt\">");

		int end = buffy.length();
		if (StringUtilities.endsWithIgnoreCase(text, HTML_CLOSE)) {
			end = end - HTML_CLOSE.length();
		}

		buffy.insert(end, "</SPAN>");
		return buffy.toString();
	}

	/**
	 * Sets the font size and color of the given text by wrapping it in &lt;font&gt; tags.
	 *
	 * @param text the text to size
	 * @param color the color of the text
	 * @param ptSize the point size of the text
	 * @return the updated String
	 */
	public static String setFont(String text, Color color, int ptSize) {
		String rgb = toHexString(color);
		int start = 0;
		if (StringUtilities.startsWithIgnoreCase(text, HTML)) {
			start = HTML.length();
		}

		StringBuilder buffy = new StringBuilder(text);
		buffy.insert(start, "<SPAN STYLE=\"font-size: " + ptSize + "pt; color: " + rgb + "\">");

		int end = buffy.length();
		if (StringUtilities.endsWithIgnoreCase(text, HTML_CLOSE)) {
			end = end - HTML_CLOSE.length();
		}

		buffy.insert(end, "</SPAN>");
		return buffy.toString();
	}

	/**
	 * Returns the given text wrapped in {@link #LINK_PLACEHOLDER_OPEN} and close tags.
	 * If <code>foo</code> is passed for the HTML text, with a content value of <code>123456</code>, then
	 * the output will look like:
	 * <pre>
	 * 	&lt;!-- LINK CONTENT="123456" --&gt;foo&lt;!-- /LINK --&gt;
	 * </pre>
	 *
	 * @param htmlText the HTML text to wrap
	 * @param content the value that will be put into the <code>CONTENT</code> section of the
	 * 		  generated HTML.  This can later be retrieved by clients transforming this text.
	 * @return the wrapped text
	 */
	public static String wrapWithLinkPlaceholder(String htmlText, String content) {

		String openTag =
			LINK_PLACEHOLDER_OPEN.replace(LINK_PLACEHOLDER_CONTENT, "CONTENT=\"" + content + "\"");
		return openTag + htmlText + LINK_PLACEHOLDER_CLOSE;
	}

	/**
	 * Takes HTML text wrapped by {@link #wrapWithLinkPlaceholder(String, String)} and replaces
	 * the custom link comment tags with HTML anchor (<code>A</code>) tags, where the <code>HREF</code>
	 * value is the value that was in the <code>CONTENT</code> attribute.
	 *
	 * @param text the text for which to replace the markup
	 * @return the updated text
	 */
	public static String convertLinkPlaceholdersToHyperlinks(String text) {

		Pattern p = Pattern.compile("<!-- LINK CONTENT=\"(.*?)\" -->");

		StringBuffer buffy = new StringBuffer();
		Matcher matcher = p.matcher(text);
		while (matcher.find()) {
			String content = matcher.group(1);
			String escaped = content.replace("$", "\\$");
			String updated = "<A HREF=\"" + escaped + "\">";
			matcher.appendReplacement(buffy, updated);
		}

		matcher.appendTail(buffy);

		String pass1 = buffy.toString();
		String pass2 = pass1.replaceAll(LINK_PLACEHOLDER_CLOSE, "</A>");
		return pass2;
	}

	/**
	 * Convert the given string to HTML by adding the HTML tag and
	 * replacing new line chars with HTML &lt;BR&gt; tags.
	 *
	 * @param text The text to convert to HTML
	 * @return the converted text
	 */
	public static String toHTML(String text) {
		int noMax = 0;
		String html = toWrappedHTML(text, noMax);
		return html;
	}

	/**
	 * This is just a convenience method to call {@link #toWrappedHTML(String, int)} with a
	 * max line length of {@value #DEFAULT_MAX_LINE_LENGTH}.
	 *
	 * @param text The text to convert
	 * @return converted text
	 */
	public static String toWrappedHTML(String text) {
		return toWrappedHTML(text, DEFAULT_MAX_LINE_LENGTH);
	}

	/**
	 * Similar to {@link #toHTML(String)} in that it will wrap the given text in
	 * HTML tags and split the content into multiple lines.  The difference is that this method
	 * will split lines that pass the given maximum length <b>and</b> on <code>'\n'</code>
	 * characters.  Alternatively, {@link #toHTML(String)} will only split the given
	 * text on <code>'\n'</code> characters.
	 *
	 * @param text The text to convert
	 * @param maxLineLength The maximum number of characters that should appear in a line;
	 * 		  0 signals not to wrap the line based upon length
	 * @return converted text
	 */
	public static String toWrappedHTML(String text, int maxLineLength) {

		if (text == null) {
			return null;
		}

		String wrappedLine = lineWrapWithHTMLLineBreaks(text, maxLineLength);
		if (isHTML(text)) {
			return wrappedLine;
		}

		return HTML + fixupHTMLRenderingIssues(wrappedLine);

	}

	/**
	 * A very specific method that will:
	 * <ol>
	 * 	<li>
	 * 	Make sure the HTML length is clipped to a reasonable size
	 *  </li>
	 *  <li>
	 *  <b>Escape any embedded HTML</b> (so that it is not interpreted as HTML)
	 *  </li>
	 *  <li>
	 *  Put the entire result in HTML
	 *  </li>
	 * </ol>
	 *
	 * @param text the text to convert
	 * @return the converted value.
	 */
	public static String toLiteralHTMLForTooltip(String text) {

		if (text.length() > MAX_TOOLTIP_LENGTH) {
			text = text.substring(0, MAX_TOOLTIP_LENGTH) + "...";
		}

		String html =
			toHTMLWithLineWrappingAndEncoding(text, DEFAULT_TOOLTIP_MAX_LINE_LENGTH, false);
		return html;
	}

	/**
	 * Converts any special or reserved characters in the specified string into HTML-escaped
	 * entities.  Use this method when you have content containing HTML that you do not want
	 * interpreted as HTML, such as when displaying text that uses angle brackets around words.
	 *
	 * <P>For example, consider the following<br><br>
	 *
	 * <table border=1><caption></caption>
	 * 		<tr>
	 * 			<th>Input</th><th>Output</th><th>Rendered as</th><th>(Without Friendly Encoding)</th>
	 * 		</tr>
	 * 		<tr>
	 * 			<td>
	 * 				Hi &lt;b&gt;mom &lt;/b&gt;
	 * 			</td>
	 * 			<td>
	 * 				Hi<span style="color:green">
	 *  &#x26;nbsp;<b>&#x26;lt;</b></span>b<span style="color:green"><b>&#x26;gt;</b></span>mom
	 *  <span style="color:green">&#x26;nbsp;<b>&#x26;lt;</b></span>/b<span style="color:green"><b>&#x26;gt;</b>
	 *  </span>
	 * 			</td>
	 * 			<td>
	 * 				Hi &lt;b&gt;mom &lt;/b&gt;
	 * 			</td>
	 * 			<td>
	 * 				Hi <b>mom </b>
	 * 			</td>
	 * 		</tr>
	 * </table>
	 *
	 *  <br><br><br>
	 *
	 * @param text string to be encoded
	 * @return the encoded HTML string
	 */
	public static String friendlyEncodeHTML(String text) {
		return friendlyEncodeHTML(text, true);
	}

	/**
	 * See {@link #friendlyEncodeHTML(String)}
	 * 
	 * @param text string to be encoded
	 * @param skipLeadingWhitespace  true signals to ignore any leading whitespace characters.
	 * 	      This is useful when line wrapping to force wrapped lines to the left
	 * @return the encoded HTML string
	 */
	private static String friendlyEncodeHTML(String text, boolean skipLeadingWhitespace) {

		StringBuilder buffer = new StringBuilder();

		int i = 0;
		int col = 0;
		if (skipLeadingWhitespace) {
			for (i = 0; i < text.length(); i++) { // skip leading spaces.
				if (!Character.isWhitespace(text.charAt(i))) {
					break;
				}
			}
		}
		for (; i < text.length(); i++) {
			char c = text.charAt(i);
			if (c == '\r') {
				// Strip CR and reset column
				col = 0;
				continue;
			}
			else if (c == '\n') {
				buffer.append(c);
				col = 0;
				continue;
			}
			else if (c == '\t') {
				int cnt = TAB_SIZE - (col % TAB_SIZE);
				for (int k = 0; k < cnt; k++) {
					buffer.append(HTML_SPACE);
				}
				col = 0;
				continue;
			}
			else if (c == ' ') {
				buffer.append(HTML_SPACE);
			}
			else if (c < ' ') {
				// Strip other non-printing chars
				continue;
			}
			else if (c > 0x7F) {
				buffer.append("&#x");
				buffer.append(Integer.toString(c, 16).toUpperCase());
				buffer.append(";");
			}
			else {
				switch (c) {
					case '&':
						buffer.append("&amp;");
						break;
					case '<':
						buffer.append("&lt;");
						break;
					case '>':
						buffer.append("&gt;");
						break;
					case 0x7F:
						break;
					default:
						buffer.append(c);
						break;
				}
			}
			++col;
		}

		return buffer.toString();
	}

	/**
	 * Escapes any HTML special characters in the specified text.
	 * <p>
	 * Does not otherwise modify the input text or wrap lines.
	 * <p>
	 * Calling this twice will result in text being double-escaped, which will not display correctly.
	 * <p>
	 * See also <code>StringEscapeUtils#escapeHtml3(String)</code> if you need quote-safe html encoding.
	 * <p>
	 *  
	 * @param text plain-text that might have some characters that should NOT be interpreted as HTML
	 * @return string with any html characters replaced with equivalents
	 */
	public static String escapeHTML(String text) {

		StringBuilder buffer = new StringBuilder(text.length());
		text.codePoints().forEach(cp -> {
			switch (cp) {
				case '&':
					buffer.append("&amp;");
					break;
				case '<':
					buffer.append("&lt;");
					break;
				case '>':
					buffer.append("&gt;");
					break;
				default:
					if (charNeedsHTMLEscaping(cp)) {
						buffer.append("&#x");
						buffer.append(Integer.toString(cp, 16).toUpperCase());
						buffer.append(";");
					}
					else {
						buffer.appendCodePoint(cp);
					}
					break;
			}
		});

		return buffer.toString();
	}

	/**
	 * Tests a unicode code point (i.e., 32 bit character) to see if it needs to be escaped before 
	 * being added to a HTML document because it is non-printable or a non-standard control 
	 * character
	 * 
	 * @param codePoint character to test
	 * @return boolean true if character should be escaped
	 */
	public static boolean charNeedsHTMLEscaping(int codePoint) {
		if (codePoint == '\n' || codePoint == '\t' || (' ' <= codePoint && codePoint < 0x7F)) {
			return false;
		}
		return true;
	}

	/**
	 * A convenience method to split the given HTML into lines, based on the given length, and
	 * then to {@link #friendlyEncodeHTML(String)} the text.
	 *
	 * <P>This method preserves all whitespace between line breaks.
	 *
	 * <P><B>Note: </B>This method is not intended to handle text that already contains
	 * entity escaped text.  The result will not render correctly as HTML.
	 *
	 * @param text the text to update
	 * @param maxLineLength the max line length upon which to wrap; 0 for no max length
	 * @return the updated text
	 */
	public static String toLiteralHTML(String text, int maxLineLength) {
		String html = toHTMLWithLineWrappingAndEncoding(text, maxLineLength, true);
		return html;
	}

	private static String toHTMLWithLineWrappingAndEncoding(String text, int maxLineLength,
			boolean preserveLeadingWhitespace) {

		StringBuilder buffy = new StringBuilder();
		List<String> lines = HtmlLineSplitter.split(text, maxLineLength, preserveLeadingWhitespace);
		for (int i = 0; i < lines.size(); i++) {
			String line = lines.get(i);
			buffy.append(friendlyEncodeHTML(line, !preserveLeadingWhitespace));

			if (i + 1 < lines.size()) {
				// don't add to the end
				buffy.append(BR).append('\n');
			}
		}

		String html = wrapAsHTML(buffy.toString());
		return html;
	}

	/**
	 * This is just a convenience call to {@link #lineWrapWithHTMLLineBreaks(String, int)} with
	 * a max line length of 0, which signals to not to wrap on line length, but only on
	 * newline characters.
	 *
	 * @param text the text to wrap
	 * @return the updated text
	 * @see #lineWrapWithHTMLLineBreaks(String, int)
	 */
	public static String lineWrapWithHTMLLineBreaks(String text) {
		return lineWrapWithHTMLLineBreaks(text, 0);
	}

	/**
	 * Replaces all newline characters with HTML &lt;BR&gt; tags.
	 *
	 * <P>Unlike {@link #toWrappedHTML(String)}, this method does <B>not</B> add the
	 * &lt;HTML&gt; tag to the given text.
	 *
	 * <P>Call this method when you wish to create your own HTML content, with parts of that
	 * content line wrapped.
	 *
	 * @param text the text to wrap
	 * @param maxLineLength the max length of the line; 0 if no max is desired
	 * @return the updated text
	 */
	public static String lineWrapWithHTMLLineBreaks(String text, int maxLineLength) {

		if (isUnbreakableHTML(text)) {
			logUnbreakableHTMLWarning();
			return text;
		}

		List<String> lines = HtmlLineSplitter.split(text, maxLineLength);

		StringBuilder buffer = new StringBuilder();
		for (int n = 0; n < lines.size(); n++) {
			String line = lines.get(n);
			buffer.append(line);
			if (n != (lines.size() - 1)) {
				// Terminate line if not the last line
				buffer.append(BR);
				buffer.append('\n');
			}
		}
		return buffer.toString();
	}

	/**
	 * Checks the given string to see it is HTML, according to {@link BasicHTML} and then
	 * will return the text without any markup tags if it is.
	 *
	 * @param text the text to convert
	 * @return the converted String
	 */
	public static String fromHTML(String text) {

		if (text == null) {
			return null;
		}

		if (!BasicHTML.isHTMLString(text)) {
			// the message may still contain HTML, but that is something we don't handle
			return text;
		}

		//
		// Use the label's builtin handling of HTML text via the HTMLEditorKit
		//
		Swing.assertSwingThread("This method must be called on the Swing thread");
		JLabel label = new JLabel(text) {
			@Override
			public void paint(Graphics g) {
				// we cannot use paint, as we are not parented; change paint to call
				// something that works
				super.paintComponent(g);
			}
		};
		View v = (View) label.getClientProperty(BasicHTML.propertyKey);
		if (v == null) {
			return text;
		}

		//
		// Use some magic to turn the painting into text
		//
		Dimension size = label.getPreferredSize();
		label.setBounds(new Rectangle(0, 0, size.width, size.height));

		// Note: when laying out an unparented label, the y value will be half of the height
		Rectangle bounds =
			new Rectangle(-size.width, -size.height, size.width * 2, size.height * 10);

		TextLayoutGraphics g = new TextLayoutGraphics();
		g.setClip(bounds);
		label.paint(g);
		g.flush();
		String raw = g.getBuffer();
		raw = raw.trim(); // I can't see any reason to keep leading/trailing newlines/whitespace

		String updated = replaceKnownSpecialCharacters(raw);

		//
		// Unfortunately, the label adds odd artifacts to the output, like newlines after
		// formatting tags (like <B>, <FONT>, etc).   So, just normalize the text, not
		// preserving any of the line breaks.
		//
		// Note: Calling this method here causes unwanted removal of newlines.  If the original 
		//       need for this call is found, this can be revisited. 
		//       (see history for condense() code)
		// String condensed = condense(updated);
		return updated;
	}

	/**
	 * A method to remove characters from the given string that are output by the HTML
	 * conversion process when going from HTML to plain text.
	 *
	 * @param s the string to be updated
	 * @return the updated String
	 */
	private static String replaceKnownSpecialCharacters(String s) {
		StringBuilder buffy = new StringBuilder();

		s.chars().forEach(c -> {
			switch (c) {
				case 0xA0:
					buffy.append((char) 0x20);
					break;
				default:
					buffy.append((char) c);
			}
		});

		return buffy.toString();
	}

	/**
	 * Returns a color string of the format rrrgggbbb.  As an example, {@link Color#RED} would be
	 * returned as 255000000 (the values are padded with 0s to make to fill up 3 digits per
	 * component).
	 *
	 * @param color The color to convert.
	 * @return a string of the format rrrgggbbb.
	 */
	public static String toRGBString(Color color) {
		StringBuilder buffy = new StringBuilder();
		buffy.append(StringUtilities.pad(Integer.toString(color.getRed()), '0', 3));
		buffy.append(StringUtilities.pad(Integer.toString(color.getGreen()), '0', 3));
		buffy.append(StringUtilities.pad(Integer.toString(color.getBlue()), '0', 3));
		return buffy.toString();
	}

	/**
	 * Returns a color string of the format #RRGGBB.  As an example, {@link Color#RED} would be
	 * returned as #FF0000 (the values are padded with 0s to make to fill up 2 digits per
	 * component).
	 *
	 * @param color The color to convert.
	 * @return a string of the format #RRGGBB.
	 */
	public static String toHexString(Color color) {
		// this will format a color value as a 6 digit hex string (e.g. #rrggbb)
		return String.format("#%06X", color.getRGB() & 0xffffff);
	}

}
