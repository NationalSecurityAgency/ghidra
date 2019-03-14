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
 * This class represents a pin pointer managed property within a Microsoft mangled symbol.
 */
public class MDPinPointerProperty extends MDManagedProperty {
//
//	private static final String prefixEmitClause = "cli::pin_ptr<";
//	private static final String suffixEmitClause = ">";
//
	public MDPinPointerProperty(MDMang dmang) {
		super(dmang);
	}

//	public MDPinPointerProperty(String modifierTypeName, MDMang dmang)
//			throws MDException {
//		super(modifierTypeName, dmang);
//	}
//
//	@Override
//	void parseCVMod(MDMang dmang) throws MDException {
//		//blank (no cvmod);
//	}
//
//	@Override
//	void emitCVMod(StringBuilder builder) {
//		//blank (no cvmod)
//	}
//
//	@Override
//	public String emit(StringBuilder builder) {
//		if (!"".equals(modifierTypeName)) {
//			builder.insert(0, prefixEmitClause);
//			builder.append(suffixEmitClause);
//		}
//		super.emit(builder);
////		if (modifierTypeName.equals("*")) {
////			builder.append(modifierTypeName);
////		}
////		else if (modifierTypeName.equals("%")) {
////
////		}
////		else {
////			builder.append(modifierTypeName);
////		}
//		return builder.toString();
//	}
}

/******************************************************************************/
/******************************************************************************/
