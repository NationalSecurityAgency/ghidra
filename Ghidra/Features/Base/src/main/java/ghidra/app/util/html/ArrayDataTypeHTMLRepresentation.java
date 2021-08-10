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

import java.awt.Color;

import ghidra.app.util.ToolTipUtils;
import ghidra.app.util.html.diff.DataTypeDiff;
import ghidra.app.util.html.diff.DataTypeDiffBuilder;
import ghidra.program.model.data.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.StringUtilities;

public class ArrayDataTypeHTMLRepresentation extends HTMLDataTypeRepresentation {

	private ValidatableLine headerContent;
	private String bodyHtml;
	private ValidatableLine footerContent;
	private Array array;

	private String truncatedHtmlData;

	public ArrayDataTypeHTMLRepresentation(Array array) {

		this.array = array;
		this.headerContent = buildHeaderContent();
		this.bodyHtml = buildBodyHTML(false);
		this.footerContent = buildFooterContent();

		originalHTMLData = buildHTMLText(headerContent, bodyHtml, footerContent, false);

		String trimmedBodyHtml = buildBodyHTML(true);
		truncatedHtmlData = buildHTMLText(headerContent, trimmedBodyHtml, footerContent, true);
	}

	private ArrayDataTypeHTMLRepresentation(Array array, ValidatableLine headerContent,
			String bodyHtml, ValidatableLine footerContent) {
		this.array = array;
		this.headerContent = headerContent;
		this.bodyHtml = bodyHtml;
		this.footerContent = footerContent;

		originalHTMLData = buildHTMLText(headerContent, bodyHtml, footerContent, false);

		String trimmedBodyHtml = buildBodyHTML(true);
		truncatedHtmlData = buildHTMLText(headerContent, trimmedBodyHtml, footerContent, true);
	}

	private DataType getBaseDataType() {
		DataType baseDataType = array;
		while (baseDataType instanceof Array) {
			Array baseArray = (Array) baseDataType;
			baseDataType = baseArray.getDataType();
		}
		return baseDataType;
	}

	private String buildBodyHTML(boolean trim) {
		StringBuilder buffy = new StringBuilder();

		DataType baseDataType = getBaseDataType();
		buffy.append("Array Base Data Type: ").append(BR);
		buffy.append(INDENT_OPEN);

		if (baseDataType instanceof BuiltInDataType) {
			String simpleName = baseDataType.getClass().getSimpleName();
			buffy.append(simpleName);
			addDataTypeLength(baseDataType, buffy);
		}
		else {

			HTMLDataTypeRepresentation representation =
				ToolTipUtils.getHTMLRepresentation(baseDataType);

			String baseHTML = representation.getFullHTMLContentString();
			if (trim) {
				baseHTML = representation.getHTMLContentString();
			}

			buffy.append(baseHTML);

			if (baseHTML.indexOf(LENGTH_PREFIX) < 0) {
				addDataTypeLength(baseDataType, buffy);
			}
		}

		buffy.append(INDENT_CLOSE);

		return buffy.toString();
	}

	private ValidatableLine buildHeaderContent() {
		StringBuilder buffy = new StringBuilder();
		buffy.append(FORWARD_SLASH).append(FORWARD_SLASH).append(HTML_SPACE);
		buffy.append(HTMLUtilities.friendlyEncodeHTML(array.getName()));
		return new TextLine(buffy.toString());
	}

	private ValidatableLine buildFooterContent() {
		int len = array.getLength();
		if (array.isZeroLength()) {
			return new TextLine("Size: 0 (reported size is " + len + ")");
		}
		return new TextLine("Size: " + len);
	}

	private String buildHTMLText(ValidatableLine header, String body, ValidatableLine info,
			boolean trim) {

		StringBuilder buffy = new StringBuilder();

		TextLine headerLine = (TextLine) header;
		String headerText = header.getText();
		if (trim) {
			headerText = StringUtilities.trimMiddle(headerText, ToolTipUtils.LINE_LENGTH);
		}
		headerText = wrapStringInColor(headerText, headerLine.getTextColor());
		buffy.append(headerText);

		buffy.append(BR);
		TextLine infoLine = (TextLine) info;
		String infoText = info.getText();
		infoText = wrapStringInColor(infoText, infoLine.getTextColor());
		buffy.append(infoText);

		buffy.append(BR).append(BR);
		buffy.append(body);

		return buffy.toString();
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
	public HTMLDataTypeRepresentation[] diff(HTMLDataTypeRepresentation otherRepresentation) {

		if (this == otherRepresentation) {
			return new HTMLDataTypeRepresentation[] { this, this };
		}

		if (!(otherRepresentation instanceof ArrayDataTypeHTMLRepresentation)) {
			// completely different, make it as such
			return completelyDifferentDiff(otherRepresentation);
		}

		ArrayDataTypeHTMLRepresentation other =
			(ArrayDataTypeHTMLRepresentation) otherRepresentation;

		ValidatableLine header = headerContent.copy();
		ValidatableLine footer = footerContent.copy();

		String body = bodyHtml;
		String otherBody = other.bodyHtml;
		Array otherArray = other.array;
		if (!array.isEquivalent(otherArray)) {
			//
			// Note: this is not great--just marking the entire body as different.  It would 
			//       be nicer to mark the differences line-by-line.  The issue 
			//       is that we do not know what type composes the body of the array, as it can
			//       be any type.  If we ever care about diffing arrays/pointers and such, 
			//       down through all of the types (and I don't think we will), then this entire
			//       API needs to be rewritten.  The desired API would create a tree-like 
			//       structure of objects (as opposed to HTML strings), which can give our 
			//       body parts (header, body, footer), which can then be decorated via HTML
			//       as needed by the parent nodes.  Right now all we can do is ask the child 
			//       'representation' for its HTML.  This limits how we style the display of 
			//       each representation.  In the end, this API is not used much and is a 
			//       simple tool for showing data type differences, usually for two objects 
			//       that are the same data type, thus only showing minor differences.  This 
			//       API mostly works for that.
			//
			body = wrapStringInColorUsingDiv(body, DIFF_COLOR);
			otherBody = wrapStringInColorUsingDiv(otherBody, DIFF_COLOR);
		}

		ValidatableLine otherHeader = other.headerContent.copy();
		ValidatableLine otherFooter = other.footerContent.copy();

		DataTypeDiff headerDiff =
			DataTypeDiffBuilder.diffHeader(getDiffInput(header), getDiffInput(otherHeader));
		DataTypeDiff footerDiff =
			DataTypeDiffBuilder.diffLines(getDiffInput(footer), getDiffInput(otherFooter));

		return new HTMLDataTypeRepresentation[] {
			new ArrayDataTypeHTMLRepresentation(array, headerDiff.getLeftLines().get(0), body,
				footerDiff.getLeftLines().get(0)),
			new ArrayDataTypeHTMLRepresentation(other.array, headerDiff.getRightLines().get(0),
				otherBody, footerDiff.getRightLines().get(0)) };
	}

	// note: getting the color to work for nested data structures when we are not building them
	//       proved quite difficult.  Here we hack something that is different than the base
	//       way of coloring.
	protected static String wrapStringInColorUsingDiv(String string, Color color) {
		if (color == null) {
			return string;
		}

		String rgb = HTMLUtilities.toHexString(color);
		return "<DIV STYLE='color: " + rgb + ";'>" + string + "</DIV>";
	}
}
