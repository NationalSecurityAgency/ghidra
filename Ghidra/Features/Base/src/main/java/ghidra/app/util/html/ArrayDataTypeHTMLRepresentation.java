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

public class ArrayDataTypeHTMLRepresentation extends HTMLDataTypeRepresentation {

	private ValidatableLine headerContent;
	private String bodyHtml;
	private ValidatableLine footerContent;
	private Array array;

	public ArrayDataTypeHTMLRepresentation(Array array) {

		this.array = array;
		this.headerContent = buildHeaderContent();
		this.bodyHtml = buildBodyHTML();
		this.footerContent = buildFooterContent();
		originalHTMLData = buildHTMLText(headerContent, bodyHtml, footerContent);
	}

	private ArrayDataTypeHTMLRepresentation(Array array, ValidatableLine headerContent,
			String bodyHtml, ValidatableLine footerContent) {
		this.array = array;
		this.headerContent = headerContent;
		this.bodyHtml = bodyHtml;
		this.footerContent = footerContent;
		originalHTMLData = buildHTMLText(headerContent, bodyHtml, footerContent);
	}

	private DataType getBaseDataType() {
		DataType baseDataType = array;
		while (baseDataType instanceof Array) {
			Array baseArray = (Array) baseDataType;
			baseDataType = baseArray.getDataType();
		}
		return baseDataType;
	}

	private String buildBodyHTML() {
		StringBuffer buffy = new StringBuffer();

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
			String baseHTML = representation.getHTMLContentString();

			buffy.append(baseHTML);

			if (baseHTML.indexOf(LENGTH_PREFIX) < 0) {
				addDataTypeLength(baseDataType, buffy);
			}
		}

		buffy.append(INDENT_CLOSE);

		return buffy.toString();
	}

	private ValidatableLine buildHeaderContent() {
		StringBuffer buffy = new StringBuffer();
		buffy.append(FORWARD_SLASH).append(FORWARD_SLASH).append(HTML_SPACE);

		String description = "Array of ";
		DataType baseDataType = array;
		while (baseDataType instanceof Array) {
			Array baseArray = (Array) baseDataType;
			description += baseArray.getNumElements() + " elements of ";
			baseDataType = baseArray.getDataType();
		}
		description += HTMLUtilities.friendlyEncodeHTML(baseDataType.getName());
		buffy.append(description);
		return new TextLine(buffy.toString());
	}

	private ValidatableLine buildFooterContent() {
		return new TextLine("Size: " + array.getLength());
	}

	private String buildHTMLText(ValidatableLine header, String body, ValidatableLine footer) {

		StringBuffer buffy = new StringBuffer();

		TextLine headerLine = (TextLine) header;
		String headerText = header.getText();
		headerText = wrapStringInColor(headerText, headerLine.getTextColor());
		buffy.append(headerText);

		buffy.append(BR).append(BR);
		buffy.append(body);

		// footer
		buffy.append(BR);
		TextLine footerLine = (TextLine) footer;
		String footerText = footer.getText();
		footerText = wrapStringInColor(footerText, footerLine.getTextColor());
		buffy.append(footerText);
		return buffy.toString();
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
