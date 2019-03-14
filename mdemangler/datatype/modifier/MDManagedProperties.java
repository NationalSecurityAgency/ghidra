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

import mdemangler.*;

/******************************************************************************/

/******************************************************************************/
// DO NOT DELETE THE CODE BELOW!!!
//  It is work in progress, trying to find the right hierarchical structures
//  and output mechanisms that will make everything better.
/******************************************************************************/
/******************************************************************************/

/**
 * TBD
 */
public class MDManagedProperties extends MDParsableItem {
	boolean isPointer;
	boolean isReference;
	boolean isGC;
	boolean isPin;
	boolean isC;
//	boolean isF;
//	boolean isH;
//	boolean isQ;
	String special; // TODO: Name this better once understood. For now, special pointer
//	boolean isTypeInfo; // 20140506

	boolean isCLI;
	boolean isCliArray;
	int arrayRank;

	public MDManagedProperties(MDMang dmang, boolean isPointer, boolean isReference) {
		super(dmang);
		this.isPointer = isPointer;
		this.isReference = isReference;
	}

	// TODO: Not sure if any of these cases have options... if not, could simplify accessor
	//  routines down to one, which returns the code character.
	public boolean isGC() {
		return isGC;
	}

	public boolean isPin() {
		return isPin;
	}

	public boolean isC() {
		return isC;
	}

//	public boolean isF() {
//		return isF;
//	}
//	
//	public boolean isH() {
//		return isH;
//	}
//	
//	public boolean isQ() {
//		return isQ;
//	}

	public String getSpecial() {
		return special;
	}

//	public boolean isTypeInfo() {
//		return isTypeInfo;
//	}

	@Override
	protected void parseInternal() throws MDException {
		// TODO: work on this.
		// $A for __gc and $B for __pin
		// What are these?
		// Others?
		char ch = dmang.peek();
		special = "";
		if (ch == '$') {
			dmang.increment();
			ch = dmang.getAndIncrement();
			switch (ch) {
				case 'A':
					special = "^";
					isGC = true;
					isCLI = true;
					break;
				case 'B':
					special = "*";
					isPin = true;
					isCLI = true;
					break;
				case 'C':
					special = "%";
					isC = true;
					isCLI = true;
					break;
//				case 'F':
//					special = "*";
//					isTypeInfo = true;
//					isF = true;
//					break;
//				case 'H':
//					special = "*";
//					isTypeInfo = true;
//					isH = true;
//					break;
//				case 'Q':
//					special = "*";
//					isTypeInfo = true;
//					isQ = true;
//					break;
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9': {
					special = "^"; // TODO: Not sure
					// Two digit number only.  True encoding is hex: 01 - 20 (1 to 32).  But MSFT
					//  undname doesn't decode this properly (and interprets values > 'F').  To
					//  really know... start from C-Language source, which I've done.
					if (ch >= '0' && ch <= '9') {
						arrayRank = ch - '0';
					}
					else if (ch >= 'A' && ch <= 'F') {
						arrayRank = ch - 'A' + 10;
					}
					else {
						throw new MDException("invalid cli:array rank");
					}
					ch = dmang.getAndIncrement();
					if (ch >= '0' && ch <= '9') {
						arrayRank = arrayRank * 16 + ch - '0';
					}
					else if (ch >= 'A' && ch <= 'F') {
						arrayRank = arrayRank * 16 + ch - 'A' + 10;
					}
					else {
						throw new MDException("invalid cli:array rank");
					}
					// Skip next character (seems it can be any character, except possibly '$')
					dmang.increment();
					isCliArray = true;
					isCLI = true;
				}
				default:
					// Could be others.
					break;
			}

		}
	}

	public String emit(String typeName) {
		if ("*".equals(typeName)) {
			if (isGC) {
				typeName = "^";
			}
			else if (isC) {
				typeName = "%";
			}
			// No change for isPin: stays *
		}
		else if ("&".equals(typeName)) {
			if (isGC) {
				typeName = "%";
			}
			else if (isC) {
				typeName = "%";
			}
			// No change for isPin: stays &
		}
		else if (isC && (isPointer || isReference)) {
			typeName = typeName + "%";
		}
		return typeName;
	}
}

/******************************************************************************/
/******************************************************************************/
