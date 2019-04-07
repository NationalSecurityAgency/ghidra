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

import mdemangler.*;
import mdemangler.functiontype.MDFunctionType;

/**
 * This class represents a Virtual Function Adjustor (Microsoft C++ mangling parlance)
 *  derivative of MDTypeInfo.
 */
public class MDVFAdjustor extends MDMemberFunctionInfo {

	// Comment from wiki page: This kind of thunk (G,H,O,P,W,X) function is always virtual, and
	// used to represent the logical "this" adjustor property, which means an offset to the
	// true "this" value in some multiple inheritance situations.
	public MDVFAdjustor(MDMang dmang) {
		super(dmang);
		mdtype = new MDFunctionType(dmang);
		setVirtual();
		setThunk();
	}

	@Override
	protected void parseInternal() throws MDException {
		MDEncodedNumber adjustment = new MDEncodedNumber(dmang);
		adjustment.parse();
		nameModifier = "`adjustor{" + adjustment + "}' ";
		super.parseInternal(); // TODO evaluate whether parseInternal() or parse.
	}
}

/******************************************************************************/
/******************************************************************************/
