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
// 20230731: note that this class uses a CVMod type, which supports its being a MDModifierType.
public class MDArrayBasicType extends MDModifierType {

	public MDArrayBasicType(MDMang dmang) {
		super(dmang);
	}

	@Override
	protected void parseInternal() throws MDException {
		cvMod.setArrayType();
		super.parseInternal();
	}

	@Override
	protected void insertCVMod(StringBuilder builder) {
		// do nothing.
	}

	@Override
	protected void insertReferredType(StringBuilder builder) {
		StringBuilder arrayBuilder = new StringBuilder();
		arrayBuilder.append("[]");
		MDType dt = this.refType;
		while (true) {
			if (dt instanceof MDArrayReferencedType mdArrayRefType) {
				arrayBuilder.append(mdArrayRefType.getArrayString());
				dt = mdArrayRefType.getReferencedType();
			}
			else if (dt instanceof MDPointerType pointerType &&
				!pointerType.getCVMod().isFunctionPointerType()) {
				dt = pointerType.getReferencedType();
			}
			else {
				break;
			}
		}
		if ((refType instanceof MDFunctionType) && (builder.length() > 0)) {
			((MDFunctionType) refType).setFromModifier();
		}
		dt.insert(builder);
		// Following to to clean the Based5 "bug" if seen.  See comments in MDBasedAttribute.
		dmang.cleanOutput(builder);
		dmang.appendString(builder, arrayBuilder.toString());
	}

}
