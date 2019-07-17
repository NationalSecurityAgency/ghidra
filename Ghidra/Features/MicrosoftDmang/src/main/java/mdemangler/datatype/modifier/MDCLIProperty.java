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

import mdemangler.MDMang;

/**
 * This class represents a CLI managed property of a modifier type within a Microsoft
 * mangled symbol.
 */
public class MDCLIProperty extends MDManagedProperty {
//
	public MDCLIProperty(MDMang dmang) {
		super(dmang);
	}

//	public MDCLIProperty(String modifierTypeName, MDMang dmang) throws MDException {
//		super(modifierTypeName, dmang);
//	}
//
////	@Override
////	public String emit(StringBuilder builder) {
////		builder.append(modifierTypeName);
////		//builder.append("%");
////		return builder.toString();
////	}
}

/******************************************************************************/
/******************************************************************************/
