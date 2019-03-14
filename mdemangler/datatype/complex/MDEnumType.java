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
package mdemangler.datatype.complex;

import mdemangler.MDException;
import mdemangler.MDMang;

/**
 * This class represents an enum type of "complex" data type within a Microsoft mangled symbol.
 */
public class MDEnumType extends MDComplexType {
	private String enumTypeName;
	private String underlyingTypeName;
	private String underlyingFullTypeName;

	public MDEnumType(MDMang dmang) {
		super(dmang);
	}

	@Override
	protected void parseInternal() throws MDException {
		char code = dmang.getAndIncrement();
		switch (code) {
			case '0':
				enumTypeName = "enum char";
				underlyingTypeName = "char";
				underlyingFullTypeName = underlyingTypeName;
				break;
			case '1':
				enumTypeName = "enum unsigned char";
				underlyingTypeName = "char";
				underlyingFullTypeName = "unsigned char";
				// setUnsigned();
				break;
			case '2':
				enumTypeName = "enum short";
				underlyingTypeName = "short";
				underlyingFullTypeName = underlyingTypeName;
				break;
			case '3':
				enumTypeName = "enum unsigned short";
				underlyingTypeName = "short";
				underlyingFullTypeName = "unsigned short";
				// setUnsigned();
				break;
			case '4':
				enumTypeName = "enum";
				underlyingTypeName = "int";
				underlyingFullTypeName = underlyingTypeName;
				break;
			case '5':
				enumTypeName = "enum unsigned int";
				underlyingTypeName = "int";
				underlyingFullTypeName = "unsigned int";
				// setUnsigned();
				break;
			case '6':
				enumTypeName = "enum long";
				underlyingTypeName = "long";
				underlyingFullTypeName = underlyingTypeName;
				break;
			case '7':
				enumTypeName = "enum unsigned long";
				underlyingTypeName = "long";
				underlyingFullTypeName = "unsigned long";
				// setUnsigned();
				break;
			default:
				throw new MDException("Enum code not expected: " + code);
		}
		// This pushpop is for the "type" of enum.  There is an encompassing push/pop in
		//  MDParsableType.
		dmang.parseInfoPushPop(1, enumTypeName);
		super.parseInternal();
	}

	@Override
	public String getTypeName() {
		return enumTypeName;
	}

	public String getUnderlyingTypeName() {
		return underlyingTypeName;
	}

	public String getUnderlyingFullTypeName() {
		return underlyingFullTypeName;
	}
}
