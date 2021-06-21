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

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.ToolTipUtils;
import ghidra.program.model.data.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.StringUtilities;
import ghidra.util.exception.AssertException;

public class PointerDataTypeHTMLRepresentation extends HTMLDataTypeRepresentation {

	private String truncatedHtmlData;

	public PointerDataTypeHTMLRepresentation(Pointer pointer) {
		super(buildHTMLText(pointer, false));

		truncatedHtmlData = buildHTMLText(pointer, true);
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

	private static String buildHTMLText(Pointer pointer, boolean trim) {

		DataType baseDataType = pointer;
		while (baseDataType instanceof Pointer) {
			baseDataType = ((Pointer) baseDataType).getDataType();
		}

		if (baseDataType == null) {
			return getDefaultDescription(pointer);
		}

		StringBuilder buffer = new StringBuilder();
		int length = pointer.getLength();
		String bits = (length * 8) + " bit ";
		String baseName = baseDataType.getName();
		if (trim) {
			baseName = StringUtilities.trimMiddle(baseName, ToolTipUtils.LINE_LENGTH);
		}
		String fullDescription = bits + " Pointer";

		fullDescription = HTMLUtilities.friendlyEncodeHTML(fullDescription);
		buffer.append(FORWARD_SLASH).append(FORWARD_SLASH).append(HTML_SPACE);
		buffer.append(HTMLUtilities.friendlyEncodeHTML(pointer.getName()));
		buffer.append(BR);
		buffer.append(fullDescription);
		buffer.append(BR);
		buffer.append("Size: ").append((length >= 0) ? length : "default");

		buffer.append(BR).append(BR);
		buffer.append("Pointer Base Data Type: ").append(BR);
		if (baseDataType instanceof BuiltInDataType) {
			String simpleName = baseDataType.getClass().getSimpleName();
			buffer.append(INDENT_OPEN);
			buffer.append(simpleName);
			addDataTypeLength(baseDataType, buffer);
			buffer.append(INDENT_CLOSE);
		}
		else {
			buffer.append(INDENT_OPEN);

			HTMLDataTypeRepresentation representation =
				ToolTipUtils.getHTMLRepresentation(baseDataType);
			String baseHTML = representation.getFullHTMLContentString();
			if (trim) {
				baseHTML = representation.getHTMLContentString();
			}

			buffer.append(baseHTML);

			if (baseHTML.indexOf(LENGTH_PREFIX) < 0) {
				addDataTypeLength(baseDataType, buffer);
			}

			buffer.append(INDENT_CLOSE);
		}

		return buffer.toString();
	}

	private static String getDefaultDescription(Pointer pointer) {
		String description = pointer.getDescription();
		if (StringUtils.isBlank(description)) {
			description = pointer.getDisplayName();
		}

		// the base pointer description does not start with an upper case; fix it
		char firstChar = description.charAt(0);
		if (!Character.isUpperCase(firstChar)) {
			description = Character.toUpperCase(firstChar) + description.substring(1);
		}

		return description;
	}

	@Override
	public HTMLDataTypeRepresentation[] diff(HTMLDataTypeRepresentation otherRepresentation) {
		throw new AssertException("Pointer types are not diffable at this time");
	}

}
