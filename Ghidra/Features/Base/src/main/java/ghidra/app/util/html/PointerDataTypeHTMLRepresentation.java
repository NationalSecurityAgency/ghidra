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

import ghidra.app.util.ToolTipUtils;
import ghidra.program.model.data.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.exception.AssertException;

public class PointerDataTypeHTMLRepresentation extends HTMLDataTypeRepresentation {

	public PointerDataTypeHTMLRepresentation(Pointer pointer) {
		super(buildHTMLText(pointer));
	}

	private static String buildHTMLText(Pointer pointer) {
		StringBuffer buffer = new StringBuffer();
		String description = pointer.getDescription();

		if (description == null || description.length() == 0) {
			description = pointer.getDisplayName();
		}
		description = HTMLUtilities.friendlyEncodeHTML(description);
		buffer.append(description);

		// the base pointer description does not start with an upper case; fix it
		char firstChar = buffer.charAt(0);
		if (!Character.isUpperCase(firstChar)) {
			buffer.replace(0, 1, Character.toString(Character.toUpperCase(firstChar)));
		}

		DataType baseDataType = pointer;
		while (baseDataType instanceof Pointer) {
			baseDataType = ((Pointer) baseDataType).getDataType();
		}

		if (baseDataType == null) {
			return buffer.toString();
		}

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
			String baseHTML = representation.getHTMLContentString();

			buffer.append(baseHTML);

			if (baseHTML.indexOf(LENGTH_PREFIX) < 0) {
				addDataTypeLength(baseDataType, buffer);
			}

			buffer.append(INDENT_CLOSE);
		}

		buffer.append(BR);
		int length = pointer.getLength();
		buffer.append("Size: ").append((length >= 0) ? length : "default");
		return buffer.toString();
	}

	@Override
	public HTMLDataTypeRepresentation[] diff(HTMLDataTypeRepresentation otherRepresentation) {
		throw new AssertException("Pointer types are not diffable at this time");
	}

}
