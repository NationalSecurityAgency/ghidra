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

/**
 * This class represents a guard (Microsoft C++ mangling parlance)
 *  derivative of MDTypeInfo.
 */
public class MDGuard extends MDTypeInfo {

	public MDGuard(MDMang dmang) {
		super(dmang);
		mdtype = new MDType(dmang);
	}

	@Override
	public void insert(StringBuilder builder) {
		super.insert(builder);
	}

	@Override
	protected void parseInternal() throws MDException {
		MDEncodedNumber guardNumber = new MDEncodedNumber(dmang);
		guardNumber.parse();
		nameModifier = "{" + guardNumber + "}'";
		super.parseInternal();
	}
}

/******************************************************************************/
/******************************************************************************/
