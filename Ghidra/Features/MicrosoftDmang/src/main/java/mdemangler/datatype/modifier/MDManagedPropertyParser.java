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

/**
 * This class parses the mangled string at the current offset to determine and
 *  create the appropriate type of MDManagedProperty.
 */
// TODO: This is work in progress.
public class MDManagedPropertyParser {
//	boolean isPointer;
//	boolean isReference;
//	boolean isGC;
//	boolean isPin;
//	boolean isC;
//	String special; //TODO: Name this better once understood. For now, special pointer
//	boolean isCLI;
//	boolean isCliArray;
//	int arrayRank;
//
//	public MDManagedPropertyParser() {
//	}
//
//	public static MDManagedProperty parse(String modifierTypeName, MDMang dmang)
//			throws MDException {
//		CharacterIteratorAndBuilder iter = dmang.getCharacterIteratorAndBuilder();
//		//TODO: work on this.
//		// $A for __gc and $B for __pin
//		// What are these?
//		// Others?
//		MDManagedProperty managedProperty;
//
//		if (iter.peek() != '$') {
//			return null;
//		}
//		iter.getAndIncrement();
//		switch (iter.peek()) {
//			case 'A':
//				iter.getAndIncrement();
//				managedProperty = new MDGCProperty(modifierTypeName, dmang);
//				break;
//			case 'B':
//				iter.getAndIncrement();
//				managedProperty = new MDPinPointerProperty(modifierTypeName, dmang);
//				break;
//			case 'C':
//				iter.getAndIncrement();
//				managedProperty = new MDCLIProperty(modifierTypeName, dmang);
//				break;
//// 20160406 commented out				
////			case 'T':
////				iter.getAndIncrement();
////				managedProperty = new MDNullPtrProperty(modifierTypeName, dmang);
////				break;
//			case '0':
//			case '1':
//			case '2':
//			case '3':
//			case '4':
//			case '5':
//			case '6':
//			case '7':
//			case '8':
//			case '9': {
//				managedProperty = new MDCLIArrayProperty(modifierTypeName, dmang);
//				break;
//			}
//			default:
//				//Could be others.
//				iter.getAndIncrement();
//				managedProperty = new MDManagedProperty(modifierTypeName, dmang);
//				break;
//		}
//
//		return managedProperty;
//	}
}

/******************************************************************************/
/******************************************************************************/
