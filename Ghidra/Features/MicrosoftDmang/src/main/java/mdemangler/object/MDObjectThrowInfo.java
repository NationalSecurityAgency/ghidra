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
package mdemangler.object;

import mdemangler.MDException;
import mdemangler.MDMang;
import mdemangler.datatype.MDDataType;
import mdemangler.datatype.MDDataTypeParser;

/**
 * This class represents a MSFT <b><code>ThrowInfo</code></b> symbol.  We have created this
 *  object and the <b><code>MDObjectReserved</code></b> type from which it is derived.  ThrowInfo
 *  seemingly has a structure as seen in the class layout of a 32-bit binary as follows:
 * <pre>
 *       class _s__ThrowInfo	size(16):
 *       +---
 *   0   | attributes
 *   4   | pmfnUnwind
 *   8   | pForwardCompat
 *  12   | pCatchableTypeArray
 *       +---
 * </pre>
 * We have seen symbols with double underscore (usually 32-bit binary) and single underscore
 *  (usually 64-bit binary), such as:<pre>
 *   mangled = "__TI1?AUX@@";
 *   or...
 *   mangled = "_TI1?AUX@@";
 * </pre>
 */
public class MDObjectThrowInfo extends MDObjectReserved {
	private String digits;
	private MDDataType dataType;

	public MDObjectThrowInfo(MDMang dmang) {
		super(dmang);
	}

	@Override
	public void insert(StringBuilder builder) {
		super.insert(builder);
		dmang.appendString(builder, "[ThrowInfo," + digits + "]{" + dataType + "}");
	}

	@Override
	protected void parseInternal() throws MDException {
		//We are assuming that we can have more than one digit.
		//TODO: forward programming to test beyond one digit.
		digits = parseDigits(dmang);
		dataType = MDDataTypeParser.parseDataType(dmang, false);
		dataType.parse();
	}
}

/******************************************************************************/
/******************************************************************************/
