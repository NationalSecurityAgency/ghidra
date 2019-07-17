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

import mdemangler.*;
import mdemangler.datatype.extended.MDArrayReferencedType;
import mdemangler.functiontype.MDFunctionType;

/**
 * This class represents an Array Basic data type within a Microsoft mangled symbol.
 */
// TODO: Consider making this an extension of ExtendedDataType (fits with the
// other '_X' types.
// The array type, however, modifies other types...???
public class MDArrayBasicType extends MDModifierType {

	public static final String ARR_NOTATION = "[]";

	public MDArrayBasicType(MDMang dmang) {
		super(dmang);
	}

	@Override
	protected void parseInternal() throws MDException {
		cvMod.setArrayType();
		super.parseInternal();
	}

	public void appendArrayNotation(StringBuilder builder) {
		builder.append(ARR_NOTATION);
	}

	@Override
	protected void insertCVMod(StringBuilder builder) {
		// do nothing.
	}

	@Override
	protected void insertReferredType(StringBuilder builder) {
		StringBuilder arrayBuilder = new StringBuilder();
		arrayBuilder.append(ARR_NOTATION);
		arrayBuilder.append(getArrayString());
		MDType dt = this.refType;
		// TODO: see if we can change from Pointer and Ref to just ModilfierType
		// on second
		// component of if.
		// TODO: confirm and change cast to MDPointerType
		// while ((dt instanceof MDPointerType) &&
		// !((MDModifierType) dt).cvMod.isFunctionPointerType()) {
		// TODO: confirm and change cast to MDPointerType
		while (((dt instanceof MDPointerType) || (dt instanceof MDArrayReferencedType)) &&
			!((MDModifierType) dt).cvMod.isFunctionPointerType()) {
			// MDMANG SPECIALIZATION USED.
			// dmang.appendArrayNotation(arrayBuilder, this);
			arrayBuilder.append(((MDModifierType) dt).getArrayString());
			dt = ((MDModifierType) dt).refType;
		}
		if ((refType instanceof MDFunctionType) && (builder.length() > 0)) {
			((MDFunctionType) refType).setFromModifier();
		}
		dt.insert(builder);
		// Following to to clean the Based5 "bug" if seen.  See comments in MDBasedAttribute.
		dmang.cleanOutput(builder);
		dmang.appendString(builder, arrayBuilder.toString());
	}

	// Parses, but ignores CVEIF, member and based components of all types in
	// the chain of
	// nested types.
	// @Override
	// public void insert(StringBuilder builder) {
	// StringBuilder arrayBuilder = new StringBuilder();
	// arrayBuilder.append(ARR_NOTATION);
	// arrayBuilder.append(getArrayString());
	// MDType dt = this.refType;
	// //TODO: see if we can change from Pointer and Ref to just ModilfierType
	// on second component of if.
	//// while ((dt instanceof MDPointerType) &&
	//// !((MDModifierType) dt).cvMod.isFunctionPointerType()) { //TODO: confirm
	// and change cast to MDPointerType
	// while (((dt instanceof MDPointerType) || (dt instanceof
	// MDArrayReferencedType)) &&
	// !((MDModifierType) dt).cvMod.isFunctionPointerType()) { //TODO: confirm
	// and change cast to MDPointerType
	// //MDMANG SPECIALIZATION USED.
	// //dmang.appendArrayNotation(arrayBuilder, this);
	// arrayBuilder.append(((MDModifierType) dt).getArrayString());
	// dt = ((MDModifierType) dt).refType;
	// }
	// if ((refType instanceof MDFunctionType) && (builder.length() > 0)) {
	// ((MDFunctionType) refType).setFromModifier();
	// }
	// dt.insert(builder);
	// //Following to to clean the Based5 "bug" if seen.  See comments in MDBasedAttribute.
	// dmang.cleanOutput(builder);
	// dmang.appendString(builder, arrayBuilder.toString());
	// }

	// //Parses, but ignores CVEIF, member and based components of all types in
	// the chain of
	// nested types.
	// @Override
	// public void insert(StringBuilder builder) {
	// //StringBuilder arrayBuilder = new StringBuilder();
	// builder.append(ARR_NOTATION);
	// //arrayBuilder.append(getArrayString());
	// MDType dt = this.refType;
	// //TODO: see if we can change from Pointer and Ref to just ModilfierType
	// on second component of if.
	//// while ((dt instanceof MDPointerType) &&
	//// !((MDModifierType) dt).cvMod.isFunctionPointerType()) { //TODO: confirm
	// and change cast to MDPointerType
	//// builder.append(((MDModifierType) dt).getArrayString());
	//// dt = ((MDModifierType) dt).refType;
	//// }
	// if ((refType instanceof MDFunctionType) && (builder.length() > 0)) {
	// ((MDFunctionType) refType).setFromModifier();
	// }
	// dt.insert(builder);
	// //Following to to clean the Based5 "bug" if seen.
	// dmang.cleanOutput(builder);  See comments in MDBasedAttribute.
	// //dmang.appendString(builder, arrayBuilder.toString());
	// }
}
