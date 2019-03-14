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

import java.util.Objects;

import mdemangler.*;
import mdemangler.datatype.MDDataTypeParser;
import mdemangler.datatype.modifier.MDModifierType;

/**
 * This class represents an "array referenced" data type within a Microsoft mangled symbol.
 */
public class MDArrayReferencedType extends MDModifierType {

	// public static final String ARR_NOTATION = "[]";
	private String arrayString = "";
	// protected MDDataType refDataType;

	public MDArrayReferencedType(MDMang dmang) {
		super(dmang, 0);
		// cvMod.setOtherType();
		cvMod.clearProperties();
		cvMod.clearCV();
	}

	/**
	 * This method will possibly become private and also removed
	 *  from the base class.  It is used to set the arrayString.
	 *  @param arrayString -- null not permitted.
	 */
	@Override
	public void setArrayString(String arrayString) {
		this.arrayString = Objects.requireNonNull(arrayString);
	}

	@Override
	public String getArrayString() {
		return arrayString;
	}

	@Override
	protected void parseInternal() throws MDException {
		if (dmang.peek() == 'Y') {
			dmang.increment();
			MDEncodedNumber n1 = new MDEncodedNumber(dmang);
			n1.parse();
			int num = n1.getValue().intValue();
			String arrString = "";
			while (num-- > 0) {
				MDEncodedNumber n2 = new MDEncodedNumber(dmang);
				n2.parse();
				arrString = arrString + '[' + n2 + ']';
			}
			setArrayString(arrString);
			// refDataType = MDDataTypeParser.parsePrimaryDataType(dmang,
			// false);
			// refDataType.setIsReferencedType();
			// //20170523 refDataType.setIsArray();
			// dmang.parse(refDataType);
			refType = MDDataTypeParser.parsePrimaryDataType(dmang, false);
			// refType.setIsReferencedType();
			// 20170523 refType.setIsArray();
			refType.parse();
		}
	}

	@Override
	public void insert(StringBuilder builder) {
		if (!dmang.isEffectivelyEmpty(builder)) {
			dmang.insertString(builder, "(");
			dmang.appendString(builder, ")");
		}
		dmang.appendString(builder, getArrayString());
		// refDataType.insert(builder);
		refType.insert(builder);
	}
}
