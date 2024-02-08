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
package mdemangler.datatype.extended;

import mdemangler.*;
import mdemangler.datatype.MDDataType;
import mdemangler.datatype.MDDataTypeParser;

/**
 * This class represents an "array referenced" data type within a Microsoft mangled symbol.
 */
public class MDArrayReferencedType extends MDDataType {

	private String arrayString = "";

	private MDDataType refDataType;

	public MDArrayReferencedType(MDMang dmang) {
		super(dmang, 0);
	}

	public String getArrayString() {
		return arrayString;
	}

	public MDDataType getReferencedType() {
		return refDataType;
	}

	@Override
	protected void parseInternal() throws MDException {
		if (dmang.peek() == 'Y') {
			dmang.parseInfoPush(0, "Array Property");
			dmang.increment();
			MDEncodedNumber n1 = new MDEncodedNumber(dmang);
			n1.parse();
			int num = n1.getValue().intValue();
			arrayString = "";
			while (num-- > 0) {
				MDEncodedNumber n2 = new MDEncodedNumber(dmang);
				n2.parse();
				arrayString = arrayString + '[' + n2 + ']';
			}
			dmang.parseInfoPop();

			refDataType = MDDataTypeParser.parsePrimaryDataType(dmang, false);
			refDataType.parse();

		}
	}

	@Override
	public void insert(StringBuilder builder) {
		if (!dmang.isEffectivelyEmpty(builder)) {
			dmang.insertString(builder, "(");
			dmang.appendString(builder, ")");
		}
		dmang.appendString(builder, getArrayString());
		refDataType.insert(builder);
	}
}
