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
package mdemangler.functiontype;

import mdemangler.*;
import mdemangler.datatype.MDDataType;
import mdemangler.datatype.MDDataTypeParser;
import mdemangler.datatype.modifier.MDBasedAttribute;
import mdemangler.datatype.modifier.MDCVMod;

/**
 * This class represents a function within a Microsoft mangled symbol.
 */
public class MDFunctionType extends MDType {
	private MDCallingConvention convention;
	private MDDataType retType;
	private MDArgumentsList argsList;
	private MDCVMod thisPointerCVMod;
	private MDThrowAttribute throwAttribute;
	private boolean hasCVModifier = false;
	private boolean hasReturn;
	private boolean hasArgs;
	private boolean isTypeCast;
	protected boolean fromModifier = false;

	protected MDBasedAttribute based;

	public void setBased(MDBasedAttribute based) {
		this.based = based;
	}

	public MDFunctionType(MDMang dmang) {
		this(dmang, true, true);
	}

	public MDFunctionType(MDMang dmang, boolean hasArgs, boolean hasReturn) {
		super(dmang);
		this.hasArgs = hasArgs;
		this.hasReturn = hasReturn;
	}

	public MDCallingConvention getCallingConvention() {
		return convention;
	}

	public MDDataType getReturnType() {
		return retType;
	}

	public MDArgumentsList getArgumentsList() {
		return argsList;
	}

	public MDCVMod getThisPointerCVMod() {
		return thisPointerCVMod; // for "this" pointer
	}

	public MDThrowAttribute getThrowAttribute() {
		return throwAttribute;
	}

	public void setFromModifier() {
		fromModifier = true;
	}

	public void setThisPointerCVMod(MDCVMod thisPointerCVMod) {
		this.thisPointerCVMod = thisPointerCVMod;
	}

	public void setHasCVModifier() {
		hasCVModifier = true;
	}

	public boolean hasReturn() {
		return hasReturn;
	}

	public boolean hasArgs() {
		return hasArgs;
	}

	public boolean isTypeCast() {
		return isTypeCast;
	}

	public void setTypeCast() {
		isTypeCast = true;
	}

	@Override
	protected void parseInternal() throws MDException {
		super.parseInternal(); // parseInternal or dmang.parse?
		dmang.pushFunctionContext();
		if (hasCVModifier) {
			thisPointerCVMod = new MDCVMod(dmang);
			thisPointerCVMod.setThisPointerMod();
			thisPointerCVMod.parse();
		}
		convention = new MDCallingConvention(dmang);
		convention.parse();
		if (hasReturn) {
			retType = MDDataTypeParser.parseDataType(dmang, isTypeCast);
			retType.parse();
		}
		if (hasArgs) {
			argsList = new MDArgumentsList(dmang);
			argsList.parse();
			// TODO 20170323: might make sense to parse 'Z' here and simplify the internals
			//  of MDThrowAttribute.  If 'Z' not found then throwAttribute would be null here.
			throwAttribute = new MDThrowAttribute(dmang);
			throwAttribute.parse();
		}
		dmang.popContext();
	}

	@Override
	public void insert(StringBuilder builder) {
		super.insert(builder);
		String badChars = "*&( ";
		if (builder.length() != 0 && badChars.indexOf(builder.charAt(0)) == -1) {
			dmang.insertString(builder, " ");
		}
		// Separate conventionBuilder with insertion of MDBasedType is used here to reflect MSFT
		// output on underscore-based access-level types (from MDTypeInfoParser '_' prefix),
		// specifically based5 variants.  This could possibly be put into the MDMangVS2015
		//  demangler, but then we would probably need to describe the standard MDMang output
		//  as "invalid," as based-on-basedptr is supposed to be invalid. 
		StringBuilder conventionBuilder = new StringBuilder();
		convention.insert(conventionBuilder);
		if (based != null) {
			based.append(conventionBuilder);
		}
		// Following to to clean the Based5 "bug" if seen.  See comments in MDBasedAttribute.
		dmang.cleanOutput(conventionBuilder);
		dmang.insertString(builder, conventionBuilder.toString());
		//This logic moved to MdSpecialName, so that we can get a qualified name with the
		// appropriate cast-to type in the name.  Keeping here, commented out, for
		// a digestion period (20200506).
//		if (hasReturn && isTypeCast) {
//			StringBuilder retBuilder = new StringBuilder();
//			retType.insert(retBuilder);
//			dmang.appendString(builder, " ");
//			dmang.appendString(builder, retBuilder.toString());
//		}
		if (fromModifier) {
			dmang.insertString(builder, "(");
			dmang.appendString(builder, ")");
		}
		if (hasArgs & argsList != null) {
			dmang.appendString(builder, "(");
			argsList.insert(builder);
			dmang.appendString(builder, ")");
		}
		if (thisPointerCVMod != null) {
			StringBuilder cvBuilder = new StringBuilder();
			thisPointerCVMod.insert(cvBuilder);
			dmang.appendString(builder, cvBuilder.toString());
		}
		if (hasReturn && retType != null && !isTypeCast) {
			retType.insert(builder);
		}
		if (throwAttribute != null) {
			String ta = throwAttribute.toString();
			if (ta.length() != 0) {
				dmang.appendString(builder, " " + ta);
			}
		}
	}
}

/******************************************************************************/
/******************************************************************************/
