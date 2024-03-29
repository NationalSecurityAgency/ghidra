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
package ghidra.app.util.html;

import static ghidra.util.HTMLUtilities.*;

import java.awt.Color;
import java.util.*;

import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.util.datatype.DataTypeUrl;
import ghidra.program.model.data.*;
import ghidra.util.*;
import ghidra.util.exception.AssertException;

public abstract class HTMLDataTypeRepresentation {

	/**
	 * HACK: for some reason when opening the HTML document with '&#47;', all text until the
	 * next HTML tag is not displayed.  So, we put in a dummy tag and all is well.
	 * Java 1.5.0_12
	 */
	protected static final String EMPTY_TAG = "<I></I>";

	// max components to show in a tool tip for a composite or enum data type
	protected final static int MAX_COMPONENTS = 50;
	protected final static int MAX_CHARACTER_LENGTH = 80;
	protected final static int MAX_LINE_LENGTH = MAX_CHARACTER_LENGTH * 3;

	// HTML Tag constants. Intentionally lower-case to match external checks for isHtml(), some of
	// which check case-sensitive for "<html>"
	protected static final String HTML_OPEN = "<html>";
	protected static final String HTML_CLOSE = "</html>";

	// single HTML space
	protected static final String HTML_SPACE = "&nbsp;";
	protected static final String CHARACTER_SPACE = " ";

	// tab
	protected static final String TAB = createSpace(4);

	// BR - HTML break tag
	protected static final String BR = "<BR>";

	// HTMM table open and close
	protected static final String TABLE_OPEN = "<TABLE>";
	protected static final String TABLE_CLOSE = "</TABLE>";

	// HTML table row open tag
	protected static final String TR_OPEN = "<TR>";
	protected static final String TR_CLOSE = "</TR>";

	// HTML table column open tag
	protected static final String TD_OPEN = "<TD ALIGN=LEFT VALIGN=TOP>";
	protected static final String TD_CLOSE = "</TD>";

	// TT - HTML teletype font open tag
	protected static final String TT_OPEN = "<TT>";
	protected static final String TT_CLOSE = "</TT>";

	// Note 1: Indentation tags (note: we switched from <DIV> tags because the Java rendering engine
	// does not keep the color of the div's parent tags.  The <P> tag seems to work).
	// Note 2: Switch back to <DIV> from <P>, since the <P> tag gets broken by the <TABLE> tag
	// used by composite types.   If not inheriting the color becomes an issue, then we will need
	// to find another solution for indentation.
	protected static final String INDENT_OPEN = "<DIV STYLE='margin-left: 10px;'>";
	protected static final String INDENT_CLOSE = "</DIV>";

	protected static final String ELLIPSES = "...";
	protected static final String LENGTH_PREFIX = "Length: ";
	protected static final String ALIGNMENT_PREFIX = "Alignment: ";

	protected final static String FORWARD_SLASH = "&#47;";

	protected final static String START_COMMENT = FORWARD_SLASH + '*' + BR;
	protected final static String MIDDLE_COMMENT = HTML_SPACE + '*' + HTML_SPACE;
	protected final static String END_COMMENT = HTML_SPACE + '*' + FORWARD_SLASH + BR;

	protected final static Color DIFF_COLOR = ValidatableLine.INVALID_COLOR;

	private static String createSpace(int numberOfSpaces) {
		StringBuilder buffer = new StringBuilder();
		for (int i = 0; i < numberOfSpaces; i++) {
			buffer.append(HTML_SPACE);
		}
		return buffer.toString();
	}

	protected static StringBuilder addDataTypeLength(String dataTypeLengthString,
			StringBuilder buffer) {

		buffer.append(BR);
		buffer.append(LENGTH_PREFIX);
		buffer.append(dataTypeLengthString);

		return buffer;
	}

	protected static StringBuilder addDataTypeLengthAndAlignment(DataType dt,
			StringBuilder buffer) {

		buffer.append(LENGTH_PREFIX);
		buffer.append(getDataTypeLengthString(dt));
		if (dt != null && dt.getLength() >= 0) {
			buffer.append(HTML_SPACE);
			buffer.append(HTML_SPACE);
			buffer.append(ALIGNMENT_PREFIX);
			buffer.append(dt.getAlignment());
		}
		return buffer;
	}

	protected static String getDataTypeLengthString(DataType dt) {
		String lengthString = null;
		if (dt == null) {
			lengthString = "<i>Unknown</i>";
		}
		else {
			int length = dt.isZeroLength() ? 0 : dt.getLength();
			if (length >= 0) {
				lengthString = Integer.toString(length);
			}
			else {
				lengthString = " <i>Unsized</i>";
			}
		}
		return lengthString;
	}

	/**
	 * Returns the plain-text value of the data type's description.
	 * <p>
	 * If there were html tags in the string, they are escaped.
	 *
	 * @param dataType the type to get the description / comment for
	 * @return plain-text string, w/html escaped
	 */
	protected static String getCommentForDataType(DataType dataType) {
		String comment = null;
		if (dataType instanceof DataTypeComponent) {
			comment = ((DataTypeComponent) dataType).getComment();
		}
		if (comment == null) {
			comment = dataType.getDescription();
		}
		return comment == null ? "" : HTMLUtilities.escapeHTML(comment);
	}

	protected static String truncateAsNecessary(String string) {
		return truncateAsNecessary(string, MAX_CHARACTER_LENGTH);
	}

	protected static String truncateAsNecessary(String string, int length) {
		if (string == null) {
			return "";
		}

		if (string.length() > length) {
			return string.substring(0, length) + ELLIPSES;
		}
		return string;
	}

	/**
	 * Formats a multi-line plain-text comment string into a HTML string where the text has been
	 * wrapped at MAX_LINE_LENGTH.
	 *
	 * @param string plain-text string
	 * @return list of html strings
	 */
	private static List<String> breakCommentAsNecessary(String string) {
		List<String> list = new ArrayList<>();
		for (String nativeCommentLine : string.split("\n")) {
			List<String> wrappedLines = breakLongLineAtWordBoundaries(nativeCommentLine,
				MAX_CHARACTER_LENGTH - MIDDLE_COMMENT.length());
			for (int i = 0; i < wrappedLines.size(); i++) {
				String wrappedLine = wrappedLines.get(i);
				list.add(MIDDLE_COMMENT + wrappedLine + BR);
			}
		}
		return list;
	}

	/*
	 * Word wraps a text line, returning multiple strings representing the new lines created.
	 * <p>
	 * Lines are broken between words, with the word that passed over the line length limit being
	 * pushed down to the next line.
	 * <p>
	 * If a word is too long to fit on a line by itself, it is harshly dealt with and broken
	 * into arbitrarily pieces to fit the line length.
	 *
	 * @param lineStr string to word-wrap.
	 * @param maxLineLen max length of a line.
	 * @return list of strings.
	 */
	/* package */ static List<String> breakLongLineAtWordBoundaries(String lineStr,
			int maxLineLen) {
		List<String> result = new ArrayList<>();
		StringBuilder lineBuffer = new StringBuilder();

		StringTokenizer tokenizer = new StringTokenizer(lineStr, CHARACTER_SPACE, true);
		while (tokenizer.hasMoreTokens()) {
			String token = tokenizer.nextToken();
			while (!token.isEmpty()) {
				int lineCharsAvail = maxLineLen - lineBuffer.length();
				if (lineCharsAvail < token.length() && token.length() < maxLineLen) {
					result.add(lineBuffer.toString());
					lineBuffer.setLength(0);
					lineCharsAvail = maxLineLen;
				}

				int partLen = Math.min(lineCharsAvail, token.length());
				String part = token.substring(0, partLen);
				lineBuffer.append(part);
				token = token.substring(partLen);

				if (lineBuffer.length() >= maxLineLen) {
					result.add(lineBuffer.toString());
					lineBuffer.setLength(0);
				}
			}
		}
		if (lineBuffer.length() > 0) {
			result.add(lineBuffer.toString());
		}

		return result;
	}

	protected static String wrapStringInColor(String string, Color color) {
		if (color == null) {
			return string;
		}

		return HTMLUtilities.colorString(color, string);
	}

	/**
	 * Formats a multi-line plain-text comment as a list of HTML marked-up lines.
	 *
	 * @param comment multi-line plain-text string
	 * @param maxLines max number of formatted lines to return
	 * @return list of html marked-up {@link TextLine}s
	 */
	protected static List<TextLine> createCommentLines(String comment, int maxLines) {
		if (comment == null || comment.length() == 0) {
			return Collections.emptyList();
		}

		List<String> commentLines = breakCommentAsNecessary(comment);
		int origCommentLineCount = commentLines.size();
		if (origCommentLineCount > maxLines) {
			commentLines = commentLines.subList(0, maxLines - 1);
			// use the last line to indicate there is more content that could not be displayed
			commentLines.add(MIDDLE_COMMENT + "<i>" + (origCommentLineCount - maxLines + 1) +
				" lines ommitted...</i>" + BR);
		}

		List<TextLine> newList = new ArrayList<>();
		newList.add(new TextLine(START_COMMENT));
		for (String commentLine : commentLines) {
			newList.add(new TextLine(commentLine));
		}
		newList.add(new TextLine(END_COMMENT));

		/*
		 // note sure why we were add so much padding to the header
		while (newList.size() < maxLines + 2) {
			newList.add(new TextLine(BR)); // pad the end of the header for uniformity in appearance
		}
		*/

		newList.add(new TextLine(BR)); // pad the end of the header for visual separation 

		return newList;
	}

	protected String originalHTMLData;

	/** Default constructor for those who promise to later set the HTML text */
	protected HTMLDataTypeRepresentation() {
		// needed for clients what want to build-up this object later via setter methods
	}

	/*
	 * Convenience constructor for those representations that don't really do much, like diffing.
	 */
	protected HTMLDataTypeRepresentation(String htmlText) {
		this.originalHTMLData = htmlText.trim();
		// NOTE: the text expected here should not have <html></html> tags!
		boolean htmlStart = StringUtilities.startsWithIgnoreCase(htmlText, HTML_OPEN);
		boolean htmlEnd = StringUtilities.startsWithIgnoreCase(htmlText, HTML_CLOSE);
		if (htmlStart || htmlEnd) {
			throw new AssertException("Invalid HTML format: text must not include <html> tag");
		}
	}

	/**
	 * Returns an HTML string for this data representation object.  The HTML returned will be
	 * truncated if it is too long.   To get the full HTML, call {@link #getFullHTMLString()}.
	 *
	 * @return the html
	 * @see #getFullHTMLString()
	 */
	public String getHTMLString() {
		return getFullHTMLString(); // default to full text; subclasses can override
	}

	/**
	 * Returns an HTML string for this data representation object
	 *
	 * @return the html
	 * @see #getHTMLString()
	 */
	public String getFullHTMLString() {
		return HTML_OPEN + originalHTMLData + HTML_CLOSE;
	}

	/**
	 * This is like {@link #getHTMLString()}, but does not put HTML tags around the data
	 * @return the content
	 */
	public String getHTMLContentString() {
		return originalHTMLData; // default to full text; subclasses can override
	}

	/**
	* This is like {@link #getHTMLString()}, but does not put HTML tags around the data
	* @return the content
	*/
	public String getFullHTMLContentString() {
		return originalHTMLData;
	}

	/**
	 * Compares this representation and the given representation creates a diff string for both
	 * representations.
	 *
	 * @param otherRepresentation the other representation to diff against.
	 * @return An array of two strings: the first is this object's diff value, the second is the
	 *         given objects diff value.
	 */
	public abstract HTMLDataTypeRepresentation[] diff(
			HTMLDataTypeRepresentation otherRepresentation);

	protected List<ValidatableLine> buildHeaderText(DataType dataType) {

		// add the comment for the composite
		String comment = getCommentForDataType(dataType);
		List<ValidatableLine> headerLines = new ArrayList<>();
		headerLines.addAll(createCommentLines(comment, 4));

		// put the path info in; don't display a floating '/' when the path is the root path
//		CategoryPath path = dataType.getCategoryPath();
//		if (!path.equals(CategoryPath.ROOT)) {
//			headerLines.add(new TextLine(HTMLUtilities.escapeHTML(path.getPath())));
//			headerLines.add(new TextLine(BR));
//		}

		return headerLines;
	}

	protected TextLine buildFooterText(DataType dataType) {
		int length = dataType.getLength();
		if (length < 0) {
			return new TextLine(" <i>Unsized</i>");
		}

		if (dataType.isZeroLength()) {
			return new TextLine("0");
		}

		return new TextLine(
			Integer.toString(length) + " (" + NumericUtilities.toHexString(length) + ")");
	}

	private static boolean canLinkDataType(DataType dt) {
		if (dt instanceof AbstractDataType) {
			return false;
		}
		UniversalID universalID = dt.getUniversalID();
		if (universalID == null) {
			return false;
		}
		DataTypeManager dtm = dt.getDataTypeManager();
		if (dtm == null) {
			return false;
		}
		return dtm.findDataTypeForID(dt.getUniversalID()) != null;
	}

	protected static String generateTypeName(DataType dt, Color color, boolean trim) {

		String[] pointerArraySplit = splitPointerArray(dt);
		if (pointerArraySplit != null) {
			DataType baseDt = DataTypeUtils.getNamedBaseDataType(dt);
			if (baseDt != null && canLinkDataType(baseDt)) {
				dt = baseDt; // ok to split for link
			}
			else {
				pointerArraySplit = null; // do not split/link
			}
		}

		String type = dt.getName();
		if (trim) {
			type = truncateAsNecessary(type);
		}
		type = friendlyEncodeHTML(type);

		if (pointerArraySplit == null && !canLinkDataType(dt)) {
			type = wrapStringInColor(type, color);
			return type;
		}

		//
		// Markup the name with info for later hyperlink capability, as needed by the client
		//
		DataTypeUrl url = new DataTypeUrl(dt);
		String wrapped = HTMLUtilities.wrapWithLinkPlaceholder(type, url.toString());
		if (pointerArraySplit != null) {
			wrapped += friendlyEncodeHTML(pointerArraySplit[1], false);
		}
		wrapped = wrapStringInColor(wrapped, color);
		return wrapped;
	}

	private static String[] splitPointerArray(DataType dt) {

		if (!(dt instanceof Pointer) && !(dt instanceof Array)) {
			return null;
		}

		String name = dt.getName();

		int lastIndex = -1;
		int index = name.length() - 1;
		while (true) {
			if (index <= 0) {
				// unexpected condition
				lastIndex = -1;
				break;
			}
			char c = name.charAt(index);
			if (c == '*' || c == '[') {
				lastIndex = index;
			}
			else if (c != ' ' && c != ']' && !Character.isDigit(c)) {
				break;
			}
			--index;
		}

		if (lastIndex <= 0) {
			return null;
		}

		if (name.charAt(lastIndex - 1) == ' ') {
			--lastIndex;
		}

		String[] split = new String[2];
		split[0] = name.substring(0, lastIndex).trim();
		split[1] = name.substring(lastIndex);
		return split;
	}

//==================================================================================================
// Diffing Algorithm and Support
//==================================================================================================

	protected HTMLDataTypeRepresentationDiffInput getDiffInput(ValidatableLine line) {
		return new HTMLDataTypeRepresentationDiffInput(this, Arrays.asList(line));
	}

	protected HTMLDataTypeRepresentationDiffInput getDiffInput(List<ValidatableLine> lines) {
		return new HTMLDataTypeRepresentationDiffInput(this, lines);
	}

	protected HTMLDataTypeRepresentation[] completelyDifferentDiff(
			HTMLDataTypeRepresentation other) {
		return new HTMLDataTypeRepresentation[] {
			new CompletelyDifferentHTMLDataTypeRepresentationWrapper(this),
			new CompletelyDifferentHTMLDataTypeRepresentationWrapper(other) };
	}

	protected List<ValidatableLine> copyLines(List<ValidatableLine> lines) {
		List<ValidatableLine> newLines = new ArrayList<>();
		for (ValidatableLine line : lines) {
			newLines.add(line.copy());
		}
		return newLines;
	}

	protected void diffTextLine(TextLine textLine, TextLine otherTextLine) {
		if (!textLine.getText().equals(otherTextLine.getText())) {
			textLine.setValidationLine(otherTextLine);
		}
	}

	/**
	 * Extension point for adding empty lines.  Subclasses that do not wish to use the default
	 * empty text line can override this method.
	 * @param oppositeLine the line that will go along with the newly created placeholder line
	 * @return the placeholder line
	 */
	protected PlaceHolderLine createPlaceHolderLine(ValidatableLine oppositeLine) {
		// for now, base representations do not know how to create empty lines...if it turns out
		// that there is a need for one, then we can create a basic empty line to go here
		return null;
	}
}
