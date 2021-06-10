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
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;
import ghidra.util.HTMLUtilities;
import ghidra.util.exception.AssertException;

public class BitFieldDataTypeHTMLRepresentation extends HTMLDataTypeRepresentation {

	public BitFieldDataTypeHTMLRepresentation(BitFieldDataType bitFieldDt) {
		super(buildHTMLText(bitFieldDt));
	}

	private static String buildHTMLText(BitFieldDataType bitFieldDt) {
		StringBuilder buffer = new StringBuilder();

		DataType baseDataType = bitFieldDt.getBaseDataType();
		HTMLDataTypeRepresentation representation =
			ToolTipUtils.getHTMLRepresentation(baseDataType);
		String baseHTML = representation.getHTMLContentString();
		buffer.append(baseHTML);
		if (baseHTML.indexOf(LENGTH_PREFIX) < 0) {
			String lengthString = getDataTypeLengthString(bitFieldDt);
			buffer.append(LENGTH_PREFIX).append(lengthString);
		}

		String description = bitFieldDt.getDescription();

		if (StringUtils.isBlank(description)) {
			description = bitFieldDt.getDisplayName();
		}
		description = HTMLUtilities.friendlyEncodeHTML(description);
		buffer.append(description);

		buffer.append(BR).append(BR);
		buffer.append("Bitfield Base Data Type: ").append(BR);

		buffer.append(INDENT_OPEN);
		buffer.append(baseHTML);
		buffer.append(INDENT_CLOSE);

		return buffer.toString();
	}

	@Override
	public HTMLDataTypeRepresentation[] diff(HTMLDataTypeRepresentation otherRepresentation) {
		throw new AssertException("Bitfield types are not diffable at this time");
	}

}
