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
 * This class represents a vtordisp (Microsoft C++ mangling parlance)
 *  derivative of MDTypeInfo.
 */
public class MDVtordisp extends MDMemberFunctionInfo {

	// 20200507: Believe this to be <offset-to-vtordisp>
	private MDEncodedNumber vtorDisplacement;
	// 20200507: Believe this to be <static-offset>
	private MDEncodedNumber adjustment;

	public MDVtordisp(MDMang dmang) {
		super(dmang);
		mdtype = new MDFunctionType(dmang);
		vtorDisplacement = new MDEncodedNumber(dmang);
		adjustment = new MDEncodedNumber(dmang);
		setVirtual();
		setThunk();
	}

	@Override
	public String getModifier() {
		return "`vtordisp{" + vtorDisplacement + "," + adjustment + "}' ";
	}

	@Override
	protected void parseInternal() throws MDException {
		// 20200507: Believe this to be <offset-to-vtordisp>
		vtorDisplacement.parse();
		// 20200507: Believe this to be <static-offset>
		adjustment.parse();
		super.parseInternal();
	}
}

/******************************************************************************/
/******************************************************************************/
