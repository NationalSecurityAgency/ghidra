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

import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.util.HTMLUtilities;

public class DefaultDataTypeHTMLRepresentation extends HTMLDataTypeRepresentation {

	protected TextLine header;
	protected TextLine footer;

	// private constructor for making diff copies
	private DefaultDataTypeHTMLRepresentation(TextLine header, TextLine footer) {
		this.header = header;
		this.footer = footer;
		originalHTMLData = buildHTMLText(header, footer);
	}

	public DefaultDataTypeHTMLRepresentation(DataType dataType) {
		header = buildHeader(dataType);
		footer = buildFooter(dataType);
		originalHTMLData = buildHTMLText(header, footer);
	}

	private TextLine buildHeader(DataType dataType) {
		if (dataType instanceof Array) {
			Array array = (Array) dataType;
			return new TextLine(getArrayDescription(array));
		}

		String description = dataType.getDescription();
		if (description == null || description.length() == 0) {
			return new TextLine(dataType.getName());
		}
		return new TextLine(description);
	}

	private String getArrayDescription(Array array) {
		DataType baseDataType = array.getDataType();
		if (baseDataType instanceof Array) {
			return getArrayDescription((Array) baseDataType);
		}

		return "Array of " + baseDataType.getName();
	}

	private TextLine buildFooter(DataType dataType) {
		int length = dataType.getLength();
		if (length >= 0) {
			return new TextLine(Integer.toString(length));
		}
		return new TextLine(" <i>Unsized</i>");
	}

	private static String buildHTMLText(TextLine header, TextLine footer) {
		StringBuilder buffer = new StringBuilder();

		String headerText = header.getText();
		String encodedHeaderText = HTMLUtilities.escapeHTML(headerText);
		headerText = wrapStringInColor(encodedHeaderText, header.getTextColor());
		buffer.append(headerText);

		String footerText = footer.getText();
		footerText = wrapStringInColor(footerText, footer.getTextColor());
		addDataTypeLength(footerText, buffer);

		return buffer.toString();
	}

	@Override
	public HTMLDataTypeRepresentation[] diff(HTMLDataTypeRepresentation otherRepresentation) {
		if (this == otherRepresentation) {
			return new HTMLDataTypeRepresentation[] { this, this };
		}

		if (!(otherRepresentation instanceof DefaultDataTypeHTMLRepresentation)) {
			// completely different, make it as such
			return new HTMLDataTypeRepresentation[] {
				new CompletelyDifferentHTMLDataTypeRepresentationWrapper(this),
				new CompletelyDifferentHTMLDataTypeRepresentationWrapper(otherRepresentation) };
		}

		DefaultDataTypeHTMLRepresentation defaultRepresentation =
			(DefaultDataTypeHTMLRepresentation) otherRepresentation;

		TextLine diffHeader = new TextLine(header.getText());
		TextLine diffFooter = new TextLine(footer.getText());

		TextLine otherDiffHeader = new TextLine(defaultRepresentation.header.getText());
		TextLine otherDiffFooter = new TextLine(defaultRepresentation.footer.getText());

		diffTextLine(diffHeader, otherDiffHeader);
		diffTextLine(diffFooter, otherDiffFooter);

// TODO: should we treat different built in types as completely different?        

		return new HTMLDataTypeRepresentation[] {
			new DefaultDataTypeHTMLRepresentation(diffHeader, diffFooter),
			new DefaultDataTypeHTMLRepresentation(otherDiffHeader, otherDiffFooter) };
	}
}
