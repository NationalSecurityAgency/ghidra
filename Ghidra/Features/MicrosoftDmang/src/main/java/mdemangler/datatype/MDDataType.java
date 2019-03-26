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
package mdemangler.datatype;

import mdemangler.MDMang;
import mdemangler.MDType;

/**
 * This class represents the base class of a number of data types within a
 *  Microsoft mangled symbol.
 */
public class MDDataType extends MDType {
	private static final String UNSIGNED = "unsigned ";
	private static final String SIGNED = "signed ";

	// protected MDCVMod cvMod; // 20170505 late
//	private static final String CONST = "const";
//	private static final String VOLATILE = "volatile";
//
//	private boolean isConst;
//	private boolean isVolatile;

//	public MDDT() {
////		super(true);
//// 201602		typeName = "_UNKNOWNDATATYPE_ ";
//	}

	public MDDataType(MDMang dmang) {
		// super(dmang, 1);
		this(dmang, 1);
		// cvMod = new MDCVMod(dmang); // 20170505 late
	}

	public MDDataType(MDMang dmang, String typeName) {
		// super(dmang, 1);
		this(dmang, 1);
		// cvMod = new MDCVMod(dmang); // 20170505 late
		this.typeName = typeName;
	}

	public MDDataType(MDMang dmang, String typeName, int startIndexOffset) {
		// super(dmang, startIndexOffset);
		this(dmang, startIndexOffset);
		// cvMod = new MDCVMod(dmang); // 20170505 late
		this.typeName = typeName;
	}

	public MDDataType(MDMang dmang, int startIndexOffset) {
		super(dmang, startIndexOffset);
		// cvMod = new MDCVMod(dmang); // 20170505 late
	}

//	// 20170505 late: trying to move into MDCVMod directly.
//	public MDCVMod getMDCVMod() {
//		return cvMod;
//	}
//
//	// 20170505 late: trying to move into MDCVMod directly.
//	@Override
//	public void setConst() {
//		cvMod.setConst();
//	}
//
//	@Override
//	public void clearConst() {
//		cvMod.clearConst();
//	}
//
//	@Override
//	public boolean isConst() {
//		return cvMod.isConst();
//	}
//
//	@Override
//	public void setVolatile() {
//		cvMod.setVolatile();
//	}
//
//	@Override
//	public void clearVolatile() {
//		cvMod.clearVolatile();
//	}
//
//	@Override
//	public boolean isVolatile() {
//		return cvMod.isVolatile();
//	}

//	@Override
//	public void setConst() {
//		isConst = true;
//	}
//
//	@Override
//	public void clearConst() {
//		isConst = false;
//	}
//
//	@Override
//	public boolean isConst() {
//		return isConst;
//	}
//
//	@Override
//	public void setVolatile() {
//		isVolatile = true;
//	}
//
//	@Override
//	public void clearVolatile() {
//		isVolatile = false;
//	}
//
//	@Override
//	public boolean isVolatile() {
//		return isVolatile;
//	}

//	private static final char SPACE = ' ';

	//	private final String typeName;

//	protected MDCVModifier cvMod;

	private enum Signage {
		_SIGNED, _SPECIFIED_SIGNED, _UNSIGNED
	}

	private Signage sign = Signage._SIGNED;

	// 201602	private final String typeName;
	// 20160926	private String typeName = ""; // Must be "" instead of "_UNKNOWNDATATYPE_" because
	// '@' for function return type must output ""
	// 20160926: changed after allowing for a non-printing MDVoidDataType
	protected String typeName = null;

	public void setTypeName(String name) {
		typeName = name;
	}

//
//	@Override
//	public String getTypeName() {
//		return typeName;
//	}

	public void setSigned() {
		sign = Signage._SPECIFIED_SIGNED;
	}

	public boolean isSigned() {
		return sign != Signage._UNSIGNED;
	}

	public void setUnsigned() {
		sign = Signage._UNSIGNED;
	}

	public boolean isSpecifiedSigned() {
		return sign == Signage._SPECIFIED_SIGNED;
	}

	public boolean isUnsigned() {
		return sign == Signage._UNSIGNED;
	}

//	@Override
//	public void setConst() {
//		isConst = true;
//	}
//
//	@Override
//	public boolean isConst() {
//		return isConst;
//	}
//
//	@Override
//	public void setVolatile() {
//		isVolatile = true;
//	}
//
//	@Override
//	public boolean isVolatile() {
//		return isVolatile;
//	}

	public String getTypeName() {
		return typeName;
	}

	@Override
	public void insert(StringBuilder builder) {
//		StringBuilder typeName = new StringBuilder();
//		typeName.append(getTypeName());
//		if (isVolatile) {
//			builder.insertSpacedString(VOLATILE);
//		}
//		if (isConst) {
//			builder.insertSpacedString(CONST);
//		}

		if (getTypeName().length() != 0) {
			if (builder.length() != 0) {
				dmang.insertString(builder, " ");
			}
			dmang.insertString(builder, getTypeName());
		}

		if (sign == Signage._SPECIFIED_SIGNED) {
			dmang.insertSpacedString(builder, SIGNED);
		}
		if (sign == Signage._UNSIGNED) {
			dmang.insertSpacedString(builder, UNSIGNED);
		}
		// super.insert(builder);
	}
}

/******************************************************************************/
/******************************************************************************/
