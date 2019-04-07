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
package mdemangler.datatype.modifier;

import java.util.Objects;

import mdemangler.*;
import mdemangler.datatype.*;
import mdemangler.datatype.extended.MDArrayReferencedType;
import mdemangler.functiontype.MDFunctionType;

/**
 * This class represents a modifier type, whether a pointer, reference, or other
 *  special modifier type.  This class stands on its own or is extended for one
 *  of the other types.
 */
// TODO: 20160126: Maybe is should extend MDType which extends MDDT.
public class MDModifierType extends MDDataType {
	public static final char SPACE = ' ';
	private static final String CONST = "const";
	private static final String VOLATILE = "volatile";

	private boolean isConst; // 20161011: put back in
	private boolean isVolatile; // 20161011: put back in

	protected MDManagedProperty managedProperty = null;
	protected MDCVMod cvMod = null; // 20170505 late->remove this?

	protected Boolean hasCVMod = true; // 20160329
	protected MDType refType;

	// Other special types
	// private boolean isArray;
	protected String arrayString = "";

	// private String modifierTypeName = "";

	public MDModifierType(MDMang dmang) {
		super(dmang, "");
		cvMod = new MDCVMod(dmang);// 20170505late: remove this
		cvMod.setQuestionType();
	}

	public MDModifierType(MDMang dmang, int startIndexOffset) {
		super(dmang, "", startIndexOffset);
		cvMod = new MDCVMod(dmang);// 20170505late: remove this
		cvMod.setQuestionType();
	}

	public MDModifierType(MDMang dmang, String typeName) {
		super(dmang, typeName);
		cvMod = new MDCVMod(dmang);// 20170505late: remove this
		cvMod.setQuestionType();
	}

	// protected void setModifierTypeName(String modifierTypeName) {
	// this.modifierTypeName = modifierTypeName;
	// }
	//
	public MDType getReferencedType() {
		return refType;
	}

	public MDCVMod getCVMod() {
		return cvMod;
	}

	// 20170505 late: trying to move into MDCVMod directly.
	// @Override
	// public void setConst() {
	// cvMod.setConst();
	// }
	//
	// @Override
	// public void clearConst() {
	// cvMod.clearConst();
	// }
	//
	// @Override
	// public boolean isConst() {
	// return cvMod.isConst();
	// }
	//
	// @Override
	// public void setVolatile() {
	// cvMod.setVolatile();
	// }
	//
	// @Override
	// public void clearVolatile() {
	// cvMod.clearVolatile();
	// }
	//
	// @Override
	// public boolean isVolatile() {
	// return cvMod.isVolatile();
	// }

	// @Override
	public void setConst() {
		isConst = true;
	}

	// @Override
	public void clearConst() {
		isConst = false;
	}

	// @Override
	public boolean isConst() {
		return isConst;
	}

	// @Override
	public void setVolatile() {
		isVolatile = true;
	}

	// @Override
	public void clearVolatile() {
		isVolatile = false;
	}

	// @Override
	public boolean isVolatile() {
		return isVolatile;
	}

	public boolean isPointer64() {
		return cvMod.isPointer64();
	}

	public boolean isRestrict() {
		return cvMod.isRestricted();
	}

	public boolean isUnaligned() {
		return cvMod.isUnaligned();
	}

	public String getBasedName() {
		return cvMod.getBasedName();
	}

	public String getMemberScope() {
		return cvMod.getMemberScope();
	}

	protected MDDataType parseReferencedType() throws MDException {
		return MDDataTypeParser.parsePrimaryDataType(dmang, false);
	}

	@Override
	protected void parseInternal() throws MDException {
		// 20170418 dmang.pushModifierContext();
		cvMod.parse();
		if (cvMod.isFunction()) {
			MDFunctionType ft = new MDFunctionType(dmang);
			// TODO: For following line, consider member function, etc, that have additional
			// properties...// 201602
			ft.setThisPointerCVMod(cvMod.getThisPointerMDCVMod());
			refType = ft;
			// refType.setIsReferencedType();
			refType.parse();
			// 20160819 if (managedProperty == null ) {
			// if (cvMod.isPointerType() || cvMod.isReferenceType()) {
			// //20160819: might need to add more (carrot, percent)
			// if (cvMod.isFunctionPointerType() || cvMod.isReferenceType()) {
			// //20160819: might need to add more (carrot, percent)
			// ((MDFunctionType) refType).setFromModifier();
			// }
			// 20160819 if (cvMod.isFunctionPointer()) {
			// 20160930: I think the real test is:
			// if (cvMod.isPointerType()) { //20160819
			// setModifierTypeName("*");
			// }
		}
		// else if (cvMod.isFunctionPointer()) {
		// refType = new MDFunctionProperty(dmang, cvMod.getMDCVModifier(),
		// true, true);
		// }
		else { // isData
				// 20170523 attempt
			if (dmang.peek() == 'Y') {
				refType = new MDArrayReferencedType(dmang);
			}
			else {
				refType = parseReferencedType();
			}
			// parseArrayProperty(dmang);
			// //20170516 refType = MDDataTypeParser.parse(dmang, false);
			// if (arrayString != null) { //20170516
			// refType = MDDataTypeParser.parsePrimaryDataType(dmang, false);
			// }
			// else {
			// refType = parseReferencedType(dmang); //20170516
			// }
			// refType.setIsReferencedType();
			refType.parse();
		}
		// 20170418 dmang.popContext();
	}

	protected void parseArrayProperty() throws MDException {
		if (dmang.peek() == 'Y') {
			dmang.parseInfoPush(0, "Array Property");
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
			dmang.parseInfoPop();
		}
	}

	/**
	 * This method will possibly be removed from this class when we
	 *  determine how to only use it in MDArrayReference.  It is used
	 *  to set the arrayString.
	 *  @param arrayString -- null not permitted.
	 */
	public void setArrayString(String arrayString) {
		this.arrayString = Objects.requireNonNull(arrayString);
	}

	public String getArrayString() {
		return arrayString;
	}

	protected void insertCVMod(StringBuilder builder) {
		cvMod.insert(builder);
		// Following to to clean the Based5 "bug" if seen.  See comments in MDBasedAttribute.
		dmang.cleanOutput(builder); // 20170714
	}

	public void insertArrayString(StringBuilder builder) {
		// This is from 'Y' optional prefix
		// TODO: check if this should also apply to managed properties.
		if (!arrayString.isEmpty()) {
			if (!dmang.isEffectivelyEmpty(builder)) {
				dmang.insertString(builder, "(");
				dmang.appendString(builder, ")");
			}
			dmang.appendString(builder, getArrayString());
		}
	}

	protected void insertReferredType(StringBuilder builder) {
		refType.insert(builder);
	}

	@Override
	public void insert(StringBuilder builder) {
		// Added 20170412 to try have available to get MSFT affect on this
		// "invalid" condition.
		// if (cvMod.isBasedPtrBased()) {
		// builder.setLength(0);
		// }

		// 20161011: put back in: this if-block (these are for "arguments")
		// 20161025 if (builder.length() == 0) { //20161025
		if (!cvMod.isCLIArray()) {
			// 20170505 late: add this? super.insert(builder);
			if (isVolatile) {
				dmang.insertSpacedString(builder, VOLATILE);
			}
			if (isConst) {
				dmang.insertSpacedString(builder, CONST);
			}
		}
		// //TODO: This condition is the one that is not hit in the next "if"
		// statement.
		// // it is because "insert()" is overridden in the MDAarrayType class.
		// Look into
		// // whether a complete override is needed.
		// if ((refType instanceof MDFunctionType) && cvMod.isPointerType()) {
		// int a = 0;
		// int b = a;
		// }
		// if ((refType instanceof MDFunctionType) &&
		// cvMod.isFunctionPointerType()) {
		// int a = 0;
		// int b = a;
		// }
		// if ((refType instanceof MDFunctionType) && cvMod.isReferenceType()) {
		// int a = 0;
		// int b = a;
		// }
		// if ((refType instanceof MDFunctionType) &&
		// cvMod.isFunctionReferenceType()) {
		// int a = 0;
		// int b = a;
		// }
		// if ((refType instanceof MDFunctionType) && cvMod.isArrayType()) {
		// int a = 0;
		// int b = a;
		// }
		// if ((refType instanceof MDFunctionType) && (builder.length() > 0)) {
		// int a = 0;
		// int b = a;
		// }
		if ((refType instanceof MDFunctionType) && ((cvMod.isPointerType() ||
			cvMod.isFunctionPointerType() || cvMod.isReferenceType() ||
			cvMod.isFunctionReferenceType() || cvMod.isArrayType() || (builder.length() > 0)))) {
			((MDFunctionType) refType).setFromModifier();
		}
		// if (!isArray()) { //20170523
		insertCVMod(builder);
		// }
		// Following to to clean the Based5 "bug" if seen.  See comments in MDBasedAttribute.
		// 20170714 dmang.cleanOutput(builder);
		// 20170605 insertArrayString(builder); //only available for "data"
		// refType
		// TODO 20160630: Possibly insert a space here????
		// builder.insertString(" "); //20160701
		if (refType instanceof MDArrayReferencedType) {
			// 20170714 refType.insert(builder);
			insertReferredType(builder);// 20170714
		}
		else if (cvMod.isPinPointer()) {
			StringBuilder refBuilder = new StringBuilder();
			// 20170714 refType.insert(refBuilder);
			insertReferredType(refBuilder);// 20170714
			dmang.appendString(refBuilder, " ");
			if (!(cvMod.isQuestionType() ||
				(cvMod.isPointerType() && (refType instanceof MDVoidDataType)))) {
				// if ((cvMod.isPointerType()) && !(refType instanceof
				// MDVoidDataType)) {
				cvMod.insertManagedPropertiesPrefix(refBuilder);
				// MDMANG SPECIALIZATION USED.
				dmang.insertManagedPropertiesSuffix(refBuilder, cvMod);
				// cvMod.insertManagedPropertiesSuffix(refBuilder);
				// cvMod.insertManagedProperties(refBuilder);
			}
			dmang.insertString(builder, refBuilder.toString());
		}
		else if (cvMod.isCLIArray()) {
			StringBuilder refBuilder = new StringBuilder();
			// 20170714 refType.insert(refBuilder);
			insertReferredType(refBuilder);// 20170714
			if (!(refType instanceof MDVoidDataType)) {
				cvMod.insertManagedPropertiesPrefix(refBuilder);
				// cvMod.insertManagedProperties(refBuilder);
			}
			// MSFT has this outside of the test...
			cvMod.insertManagedPropertiesSuffix(refBuilder);
			// cvMod.insertManagedProperties(refBuilder);
			// TODO: make a routine in an object dispatcher for the next line,
			// subject to
			// various output modes (ED, GHIDRA, MSDN2015, etc.).
			dmang.insertCLIArrayRefSuffix(builder, refBuilder);
		}
		else {
			// 20170523 attempt
			// if (refType instanceof MDArrayReferencedType) {
			// if (!dmang.isEffectivelyEmpty(builder)) {
			// dmang.insertString(builder, "(");
			// dmang.appendString(builder, ")");
			// }
			// }
			// //Could be function (function pointer or function) or data.
			// 20170714 refType.insert(builder);
			insertReferredType(builder);// 20170714
		}
	}
}

/******************************************************************************/
/******************************************************************************/
