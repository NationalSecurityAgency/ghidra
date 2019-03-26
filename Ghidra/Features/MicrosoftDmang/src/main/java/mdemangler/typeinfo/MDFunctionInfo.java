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
import mdemangler.datatype.modifier.MDBasedAttribute;
import mdemangler.functiontype.MDFunctionType;

/**
 * This class represents a function (Microsoft C++ mangling parlance)
 *  derivative of MDTypeInfo.
 */
public class MDFunctionInfo extends MDTypeInfo {

	public void setBased(MDBasedAttribute based) {
		((MDFunctionType) mdtype).setBased(based);
	}

	public MDFunctionInfo(MDMang dmang) {
		super(dmang);
		MDFunctionType functionType = new MDFunctionType(dmang);
		mdtype = functionType;
	}

	@Override
	protected void parseInternal() throws MDException {
		MDFunctionType functionType = (MDFunctionType) mdtype;
		if (isTypeCast) {
			functionType.setTypeCast();
		}
		super.parseInternal();
	}
}

/******************************************************************************/
/******************************************************************************/
