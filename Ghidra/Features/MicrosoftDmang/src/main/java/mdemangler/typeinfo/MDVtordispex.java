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
 * This class represents a vtordispex (Microsoft C++ mangling parlance)
 *  derivative of MDTypeInfo.
 */
public class MDVtordispex extends MDMemberFunctionInfo {

	public MDVtordispex(MDMang dmang) {
		super(dmang);
		mdtype = new MDFunctionType(dmang);
		setVirtual();
		setThunk();
	}

	@Override
	protected void parseInternal() throws MDException {
		// TODO: what is this?  Possibly the displacement?
		MDEncodedNumber a = new MDEncodedNumber(dmang);
		a.parse();
		// TODO: what is this?  Possibly the adjustment?
		MDEncodedNumber b = new MDEncodedNumber(dmang);
		b.parse();
		// TODO: what is this?
		MDEncodedNumber c = new MDEncodedNumber(dmang);
		c.parse();
		// TODO: what is this?
		MDEncodedNumber d = new MDEncodedNumber(dmang);
		d.parse();
		nameModifier = "`vtordispex{" + a + "," + b + "," + c + "," + d + "}' ";
		super.parseInternal();
	}
}

/******************************************************************************/
/******************************************************************************/
