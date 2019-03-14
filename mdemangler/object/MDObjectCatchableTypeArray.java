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
 * This class represents a MSFT <b><code>CatchableTypeArray</code></b> symbol.  We have created
 *  this object and the <b><code>MDObjectReserved</code></b> type from which it is derived.
 *  <b><code>CatchableTypeArray</code></b> seemingly has a structure as seen in the class layout
 *  of a 32-bit binary as follows:
 * <pre>
 *       class _s__CatchableTypeArray	size(4):
 *       +---
 *   0   | nCatchableTypes
 *   4   | arrayOfCatchableTypes
 *       +---
 * </pre>
 * We have seen symbols with double underscore (usually 32-bit binary) and single underscore
 *  (usually 64-bit binary), such as:<pre>
 *   mangled = "__CTA1?AUX@@";
 *   or...
 *   mangled = "_CTA1?AUX@@";
 * </pre>
 */
public class MDObjectCatchableTypeArray extends MDObjectReserved {
	private String digits;
	private MDDataType dataType;

	public MDObjectCatchableTypeArray(MDMang dmang) {
		super(dmang);
	}

	@Override
	public void insert(StringBuilder builder) {
		super.insert(builder);
		dmang.appendString(builder,
			"[CatchableTypeArray," + digits + "]{" + dataType + "}");
	}

	@Override
	protected void parseInternal() throws MDException {
		//We are assuming that we can have more than one digit.
		//TODO: forward programming to test beyond one digit.
		digits = parseDigits(dmang);
		dataType = MDDataTypeParser.parseDataType(dmang, false);
		if (dataType == null) {
			throw new MDException("MDObjectCatchableTypeArray missing MDDataType");
		}
		dataType.parse();
	}
}

/******************************************************************************/
/******************************************************************************/
