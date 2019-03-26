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
package mdemangler.typeinfo;

import mdemangler.MDException;
import mdemangler.MDMang;
import mdemangler.datatype.MDDataTypeParser;
import mdemangler.datatype.modifier.MDCVMod;

/**
 * This class represents a variable derivative of MDTypeInfo.
 */
public class MDVariableInfo extends MDTypeInfo {

	private MDCVMod cvmod;

	public MDVariableInfo(MDMang dmang) {
		super(dmang);
		cvmod = new MDCVMod(dmang);
	}

	public boolean isConst() {
		return cvmod.isConst();
	}

	public boolean isVolatile() {
		return cvmod.isVolatile();
	}

	public boolean isPointer64() {
		return cvmod.isPointer64();
	}

	public boolean isRestrict() {
		return cvmod.isRestricted();
	}

	public boolean isUnaligned() {
		return cvmod.isUnaligned();
	}

	public String getBasedName() {
		return cvmod.getBasedName();
	}

	public String getMemberScope() {
		return cvmod.getMemberScope();
	}

	@Override
	public void insert(StringBuilder builder) {
		dmang.insertSpacedString(builder, " ");
		cvmod.insert(builder);
		super.insert(builder);
	}

	@Override
	protected void parseInternal() throws MDException {
		mdtype = MDDataTypeParser.parseDataType(dmang, false);
		super.parseInternal();
		cvmod.parse();
	}
}

/******************************************************************************/
/******************************************************************************/
