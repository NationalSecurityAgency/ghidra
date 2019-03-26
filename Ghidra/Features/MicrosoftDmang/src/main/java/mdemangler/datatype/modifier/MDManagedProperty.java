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
import mdemangler.MDParsableItem;

/**
 * This class represents a managed property of a modifier type within a Microsoft
 * mangled symbol.
 */
public class MDManagedProperty extends MDParsableItem {
//	protected String modifierTypeName;
//	protected MDCVMod cvmod;
//	protected MDDT mddt;
//
	public MDManagedProperty(MDMang dmang) {
		super(dmang);
	}

	protected void parseInternal() {
		// Do nothing
	}

//	void parseCVMod(MDMang dmang) throws MDException {
//		cvmod = new MDCVMod(dmang);
//	}
//
//	void emitCVMod(StringBuilder builder) {
//		cvmod.emit(builder);
//	}
//
//	public MDManagedProperty(String modifierTypeName, MDMang dmang)
//			throws MDException {
//		this.modifierTypeName = modifierTypeName;
////		parseCVMod(dmang);
////		mddt = MDDTParser.parse(dmang);
//	}
//
//	protected void parseInternal(MDMang dmang) throws MDException {
//		CharacterIteratorAndBuilder iter = dmang.getCharacterIteratorAndBuilder();
//	}
//
//	public void insert(StringBuilder builder) {
//		builder.appendString(modifierTypeName);
//	}
//
//	public String emit(StringBuilder builder) {
//		builder.append(modifierTypeName);
//
////		StringBuilder modifierTypeBuilder = new StringBuilder();
////
////		emitCVMod(modifierTypeBuilder);
////
////		Boolean insertSpace = true;
////		if ((builder.length() != 0) && (builder.charAt(0) == ' ')) {
////			insertSpace = false;
////		}
////		if (modifierTypeBuilder.length() != 0) {
////			if ((modifierTypeBuilder.charAt(modifierTypeBuilder.length() - 1) == ' ') ||
////				(modifierTypeBuilder.charAt(modifierTypeBuilder.length() - 1) == '*')) {
////				insertSpace = false;
////			}
////		}
////		if (insertSpace) {
////			builder.insert(0, ' ');
////		}
////
////		if ((modifierTypeBuilder.length() != 0) &&
////			(modifierTypeBuilder.charAt(modifierTypeBuilder.length() - 1) == ' ') &&
////			(builder.length() != 0) && (builder.charAt(0) == ' ')) {
////			modifierTypeBuilder.setLength(modifierTypeBuilder.length() - 1);
////		}
////
////		builder.insert(0, modifierTypeBuilder);
////
////		mddt.emit(builder); // could be function (function pointer or function) or data.
//
//		return builder.toString();
//	}
}

/******************************************************************************/
/******************************************************************************/
