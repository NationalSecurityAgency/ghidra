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

import java.util.*;

import ghidra.app.util.ToolTipUtils;
import ghidra.app.util.html.diff.DataTypeDiff;
import ghidra.app.util.html.diff.DataTypeDiffBuilder;
import ghidra.program.model.data.Enum;
import ghidra.util.HTMLUtilities;
import ghidra.util.StringUtilities;
import ghidra.util.exception.AssertException;

public class EnumDataTypeHTMLRepresentation extends HTMLDataTypeRepresentation {

	private static final int MAX_LINE_COUNT = 15;

	private final Enum enumDataType;

	protected List<ValidatableLine> headerContent;
	protected List<ValidatableLine> bodyContent;
	protected TextLine footerLine;
	protected TextLine displayName;

	private static String truncatedHtmlData;

	// private constructor for making diff copies
	private EnumDataTypeHTMLRepresentation(Enum enumDataType, List<ValidatableLine> headerLines,
			TextLine displayName,
			List<ValidatableLine> bodyContent, TextLine footerLine) {
		this.enumDataType = enumDataType;
		this.headerContent = headerLines;
		this.displayName = displayName;
		this.bodyContent = bodyContent;
		this.footerLine = footerLine;

		originalHTMLData =
			buildHTMLText(headerContent, displayName, bodyContent, footerLine, false);

		List<ValidatableLine> trimmedBodyContent = buildContent(true);
		truncatedHtmlData =
			buildHTMLText(headerContent, displayName, trimmedBodyContent, footerLine, true);
	}

	public EnumDataTypeHTMLRepresentation(Enum enumDataType) {
		this.enumDataType = enumDataType;
		headerContent = buildHeaderText(enumDataType);
		bodyContent = buildContent(false);
		footerLine = buildFooterText(enumDataType);
		displayName = new TextLine("enum " + enumDataType.getDisplayName());

		originalHTMLData =
			buildHTMLText(headerContent, displayName, bodyContent, footerLine, false);

		List<ValidatableLine> trimmedBodyContent = buildContent(true);
		truncatedHtmlData =
			buildHTMLText(headerContent, displayName, trimmedBodyContent, footerLine, true);
	}

	// overridden to return truncated text by default
	@Override
	public String getHTMLString() {
		return HTML_OPEN + truncatedHtmlData + HTML_CLOSE;
	}

	// overridden to return truncated text by default
	@Override
	public String getHTMLContentString() {
		return truncatedHtmlData;
	}

	@Override
	protected PlaceHolderLine createPlaceHolderLine(ValidatableLine oppositeLine) {
		if (!(oppositeLine instanceof TextLine)) {
			throw new AssertException("I didn't know you could pass me other types of lines?!");
		}
		TextLine textLine = (TextLine) oppositeLine;
		int stringLength = textLine.getText().length();
		return new EmptyTextLine(stringLength);
	}

	private List<ValidatableLine> buildContent(boolean trim) {
		long[] values = enumDataType.getValues();
		Arrays.sort(values);

		int n = enumDataType.getLength();
		List<ValidatableLine> list = new ArrayList<>(values.length);
		for (long value : values) {

			String name = enumDataType.getName(value);
			if (trim) {
				name = StringUtilities.trimMiddle(name, ToolTipUtils.LINE_LENGTH);
			}

			String hexString = Long.toHexString(value);
			if (value < 0) {
				// Long will print leading FF for 8 bytes, regardless of enum size.  Keep only
				// n bytes worth of text.  For example, when n is 2, turn FFFFFFFFFFFFFF12 into FF12
				int length = hexString.length();
				hexString = hexString.substring(length - (n * 2));
			}
			list.add(new TextLine(name + " = 0x" + hexString));
		}

		return list;
	}

	private static String buildHTMLText(List<ValidatableLine> headerLines, TextLine displayName,
			List<ValidatableLine> bodyLines, TextLine infoLine, boolean trim) {

		StringBuilder fullHtml = new StringBuilder();
		StringBuilder truncatedHtml = new StringBuilder();
		int lineCount = 0;

		// header
		Iterator<ValidatableLine> iterator = headerLines.iterator();
		for (; iterator.hasNext();) {
			TextLine line = (TextLine) iterator.next();
			String encodedHeaderLine = line.getText();
			String headerLine = wrapStringInColor(encodedHeaderLine, line.getTextColor());
			append(fullHtml, truncatedHtml, lineCount, headerLine);
			lineCount++;
		}

		append(fullHtml, truncatedHtml, lineCount, LENGTH_PREFIX, infoLine.getText());
		append(fullHtml, truncatedHtml, lineCount, BR, BR);

		// "<TT> displayName { "
		String displayNameText = displayName.getText();
		if (trim) {
			displayNameText = StringUtilities.trimMiddle(displayNameText, ToolTipUtils.LINE_LENGTH);
		}
		displayNameText = HTMLUtilities.friendlyEncodeHTML(displayNameText);
		displayNameText = wrapStringInColor(displayNameText, displayName.getTextColor());
		//@formatter:off
		append(fullHtml, truncatedHtml, lineCount, TT_OPEN, 
                                                   displayNameText,
                                                   TT_CLOSE,
                                                   HTML_SPACE,
                                                   "{",
                                                   HTML_SPACE,
                                                   BR);
		//@formatter:on
		lineCount++;

		int length = bodyLines.size();
		for (int i = 0; i < length; i++, lineCount++) {
			TextLine textLine = (TextLine) bodyLines.get(i);
			String text = textLine.getText();
			String encodedBodyLine = HTMLUtilities.friendlyEncodeHTML(text);
			text = wrapStringInColor(encodedBodyLine, textLine.getTextColor());

			StringBuilder lineBuffer = new StringBuilder();
			lineBuffer.append(TAB).append(text).append(HTML_SPACE);
			if (i < length - 1) {
				lineBuffer.append(BR);
			}

			String lineString = lineBuffer.toString();
			append(fullHtml, truncatedHtml, lineCount, lineString);
		}

		// show ellipses if needed; the truncated html is much shorter than the full html
		if (lineCount >= MAX_LINE_COUNT) {
			truncatedHtml.append(TAB).append(ELLIPSES).append(BR);
		}

		StringBuilder trailingLines = new StringBuilder();
		trailingLines.append(BR).append("}").append(BR).append(TT_CLOSE);

		String trailingString = trailingLines.toString();
		fullHtml.append(trailingString);
		truncatedHtml.append(trailingString);

		if (trim) {
			return truncatedHtml.toString();
		}
		return fullHtml.toString();
	}

	private static void append(StringBuilder fullHtml, StringBuilder truncatedHtml,
			int lineCount, String... content) {

		for (String string : content) {
			fullHtml.append(string);
		}

		maybeAppend(truncatedHtml, lineCount, content);
	}

	private static void maybeAppend(StringBuilder buffer, int lineCount, String... content) {
		if (lineCount > MAX_LINE_COUNT) {
			return;
		}

		for (String string : content) {
			buffer.append(string);
		}
	}

	@Override
	public HTMLDataTypeRepresentation[] diff(HTMLDataTypeRepresentation otherRepresentation) {
		if (this == otherRepresentation) {
			return new HTMLDataTypeRepresentation[] { this, this };
		}

		if (!(otherRepresentation instanceof EnumDataTypeHTMLRepresentation)) {
			// completely different, make it as such
			return completelyDifferentDiff(otherRepresentation);
		}

		EnumDataTypeHTMLRepresentation enumRepresentation =
			(EnumDataTypeHTMLRepresentation) otherRepresentation;

		List<ValidatableLine> header = copyLines(headerContent);
		List<ValidatableLine> body = copyLines(bodyContent);
		TextLine diffDisplayName = new TextLine(displayName.getText());

		List<ValidatableLine> otherHeader = copyLines(enumRepresentation.headerContent);
		List<ValidatableLine> otherBody = copyLines(enumRepresentation.bodyContent);
		TextLine otherDiffDisplayName = new TextLine(enumRepresentation.displayName.getText());

		DataTypeDiff headerDiff =
			DataTypeDiffBuilder.diffHeader(getDiffInput(header), getDiffInput(otherHeader));

		DataTypeDiff bodyDiff =
			DataTypeDiffBuilder.diffBody(getDiffInput(body), getDiffInput(otherBody));

		diffTextLine(diffDisplayName, otherDiffDisplayName);

		return new HTMLDataTypeRepresentation[] {
			new EnumDataTypeHTMLRepresentation(enumDataType, headerDiff.getLeftLines(),
				diffDisplayName, bodyDiff.getLeftLines(), footerLine),
			new EnumDataTypeHTMLRepresentation(enumRepresentation.enumDataType,
				headerDiff.getRightLines(), otherDiffDisplayName, bodyDiff.getRightLines(),
				enumRepresentation.footerLine)
		};
	}

}
