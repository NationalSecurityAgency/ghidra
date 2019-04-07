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
 * This class represents a Const/Volatile modifier (and extra stuff) of a modifier
 * type within a Microsoft mangled symbol.
 */
public class MDCVModifier {
//	public static final char SPACE = ' ';
//
//	public final static String PTR64 = "__ptr64";
//	private static final String UNALIGNED = "__unaligned";
//	private static final String RESTRICT = "__restrict";
//	public static final String CONST = "const";
//	public static final String VOLATILE = "volatile";
//
//	// C-V Modifiers
//	private boolean isPointer64; // Can be pointer or reference
//	private boolean isUnaligned;
//	private boolean isRestrict;
//	private boolean isConst;
//	private boolean isVolatile;
//	private boolean isFunction;
//	private boolean isBased;
//	private boolean isMember;
//	// Added C-V modifier 20140423
//	private boolean isData;
//
//	boolean isGC;
//	boolean isPin;
//	boolean isPinModifier;
//	boolean isC;
//	boolean isCliArray;
//	boolean isCLI;
//	int arrayRank;
//
//	String special; // TODO: Name this better once understood. For now, special pointer
//
//	private MDQualification qual;
//	private MDCVModifier cvMod;
//	private String basedName;
//
//	private enum CvPrefix {
//		ptr64, unaligned, restrict
//	}
//
//	private List<CvPrefix> prefixList = new ArrayList<CvPrefix>();
//
//	public MDCVModifier(MDMang dmang) throws MDException {
//		dmang.parseInfoPush(0, this.getClass().getSimpleName());
//		parse(dmang);
//		dmang.parseInfoPop();
//	}
//
//	public MDCVModifier() {
//		// use defaults
//	}
//
//	public MDCVModifier getMDCVModifier() {
//		return cvMod;
//	}
//
//	public boolean isPointer64() {
//		return isPointer64;
//	}
//
//	public boolean isUnaligned() {
//		return isUnaligned;
//	}
//
//	public boolean isRestrict() {
//		return isRestrict;
//	}
//
//	public boolean isConst() {
//		return isConst;
//	}
//
//	public boolean isVolatile() {
//		return isVolatile;
//	}
//
//	public String getBasedName() {
//		return basedName;
//	}
//
//	public boolean isBased() {
//		return !(basedName == null || "".equals(basedName));
//	}
//
//	public boolean isMember() {
//		return isMember;
//	}
//
//	public boolean isFunction() {
//		return isFunction;
//	}
//
//	public boolean isData() {
//		return isData;
//	}
//
//	private void parse(MDMang dmang) throws MDException {
//		CharacterIteratorAndBuilder iter = dmang.getCharacterIteratorAndBuilder();
//
//		boolean done = false;
//		char ch = iter.peek();
//		if (ch == '$') {
//			iter.getAndIncrement();
//			ch = iter.getAndIncrement();
//			switch (ch) {
//				case 'B':
//					isData = true;
//					isPinModifier = true;
//					done = true;
////					throw new MDException("BBBBBBBB");
//					break;
//
//				default: //We haven't seen others yet.
//					iter.previous();
//					iter.previous();
//					break;
//			}
//		}
//		if (done) {
//			return;
//		}
//
//		boolean prefixDone = false;
//		boolean previousIsMP = false;
//		while (!prefixDone) {
//			ch = iter.peek();
//			if (ch == '$') {
//				if (previousIsMP) { // Cannot allow back-to-back
//					throw new MDException("Managed Properties repeat");
//				}
//				iter.getAndIncrement();
//				ch = iter.getAndIncrement();
//				previousIsMP = true;
//				switch (ch) {
//					case 'A':
//						special = "^";
//						isGC = true;
//						break;
//					case 'B':
//						special = "*";
//						isPin = true;
//						break;
//					case 'C':
//						special = "%";
//						isC = true;
//						break;
//					case '0':
//					case '1':
//					case '2':
//					case '3':
//					case '4':
//					case '5':
//					case '6':
//					case '7':
//					case '8':
//					case '9': {
//						special = "^"; // TODO: Not sure
//						// Two digit number only.  True encoding is hex: 01 - 20 (1 to 32).
//						//  But MSFT undname doesn't decode this properly (and interprets
//						//  values > 'F').  To really know... start from C-Language source,
//						//  which I've done.
//						if (ch >= '0' && ch <= '9') {
//							arrayRank = ch - '0';
//						}
//						else if (ch >= 'A' && ch <= 'F') {
//							arrayRank = ch - 'A' + 10;
//						}
//						else {
//							throw new MDException("invalid cli:array rank");
//						}
//						ch = iter.getAndIncrement();
//						if (ch >= '0' && ch <= '9') {
//							arrayRank = arrayRank * 16 + ch - '0';
//						}
//						else if (ch >= 'A' && ch <= 'F') {
//							arrayRank = arrayRank * 16 + ch - 'A' + 10;
//						}
//						else {
//							throw new MDException("invalid cli:array rank");
//						}
//						isCliArray = true;
//					}
//						break;
//					default:
//						// Could be others.
//						break;
//				}
//			}
//			else {
//				previousIsMP = false;
//				switch (ch) {
//					case 'E':
//						isPointer64 = true;
//						prefixList.add(CvPrefix.ptr64);
//						iter.getAndIncrement();
//						break;
//					case 'F':
//						isUnaligned = true;
//						prefixList.add(CvPrefix.unaligned);
//						iter.getAndIncrement();
//						break;
//					case 'I':
//						isRestrict = true;
//						prefixList.add(CvPrefix.restrict);
//						iter.getAndIncrement();
//						break;
//					default:
//						prefixDone = true;
//						break;
//				}
//			}
//		}
//
//		// Note: Codes E, F, G, and H used to contain "far" and now are different.
//		//       E = "far" ; F = "const far" ; G = "volatile far" ; H = "const volatile far"
//		//       However, E and F are now prefixes; and G and H are grouped with others.
//		//       There is probably historical reason (look into this more?) for, for
//		//       example, C, G, and K to be the same.  Perhaps C was the small memory model,
//		//       G had far pointers, and K was huge????
//		switch (iter.getAndIncrement()) {
//			case 'A':
//				isData = true;
//				break;
//			case 'B':
//			case 'J':
//				isData = true;
//				isConst = true;
//				break;
//			case 'C':
//			case 'G':
//			case 'K':
//				isData = true;
//				isVolatile = true;
//				break;
//			case 'D':
//			case 'H':
//			case 'L':
//				isData = true;
//				isConst = true;
//				isVolatile = true;
//				break;
//			case 'M':
//				isData = true;
//				isBased = true;
//				break;
//			case 'N':
//				isData = true;
//				isConst = true;
//				isBased = true;
//				break;
//			case 'O':
//				isData = true;
//				isVolatile = true;
//				isBased = true;
//				break;
//			case 'P':
//				isData = true;
//				isConst = true;
//				isVolatile = true;
//				isBased = true;
//				break;
//			case 'Q':
//			case 'U':
//			case 'Y':
//				isData = true;
//				isMember = true;
//				break;
//			case 'R':
//			case 'V':
//			case 'Z':
//				isData = true;
//				isConst = true;
//				isMember = true;
//				break;
//			case 'S':
//			case 'W':
//			case '0':
//				isData = true;
//				isVolatile = true;
//				isMember = true;
//				break;
//			case 'T':
//			case 'X':
//			case '1':
//				isData = true;
//				isConst = true;
//				isVolatile = true;
//				isMember = true;
//				break;
//			case '2':
//				isData = true;
//				isBased = true;
//				isMember = true;
//				break;
//			case '3':
//				isData = true;
//				isConst = true;
//				isBased = true;
//				isMember = true;
//				break;
//			case '4':
//				isData = true;
//				isVolatile = true;
//				isBased = true;
//				isMember = true;
//				break;
//			case '5':
//				isData = true;
//				isConst = true;
//				isVolatile = true;
//				isBased = true;
//				isMember = true;
//				break;
//			case '6':
//			case '7':
//				isFunction = true;
//				break;
//			case '8':
//			case '9':
//				isFunction = true;
//				isMember = true;
//				break;
//			case '_':
//				isFunction = true;
//				switch (iter.getAndIncrement()) {
//					case 'A':
//					case 'B':
//						isBased = true;
//						break;
//					case 'C':
//					case 'D':
//						isBased = true;
//						isMember = true;
//						break;
//					default:
//						iter.previous();
//						break;
//				}
//				break;
//			default:
//				iter.previous();
//				break;
//		}
//		if (isMember) {
//			// qual = new MDQualification(dmang);
//			qual = new MDQualification();
//			qual.parse1(dmang);
//			if (isFunction) {
//				cvMod = new MDCVModifier(dmang);
//			}
//		}
//		if (isBased) {
//			switch (iter.getAndIncrement()) {
//				case '0':
//					basedName = "void";
//					break;
//				case '2':
//					// MDQualifiedName qn = new MDQualifiedName(dmang);
//					MDQualifiedName qn = new MDQualifiedName();
//					qn.parse1(dmang);
//					basedName = qn.emit();
//					break;
//				case '5':
//					// 20150121 basedName = "";
//					basedName = null; // 20150121
//					break;
//				default:
//					basedName = "";
//					return;
//			}
//		}
//	}
//
//	public String emit(String typeName, boolean isReferredTo, StringBuilder leftMod,
//			StringBuilder rightMod) {
////		return emit_orig(typeName, isReferredTo);
//		return emit_LR(typeName, isReferredTo, leftMod, rightMod);
//	}
//
//	public String emit_LR(String typeName, boolean isReferredTo, StringBuilder leftMod,
//			StringBuilder rightMod) {
//		StringBuffer buffer = new StringBuffer();
//		StringBuffer rightBuffer = new StringBuffer();
//		StringBuffer leftBuffer = new StringBuffer();
//		// Override typeName if necessary
//		// Note that isGC has different values for * and &
//		if ("*".equals(typeName)) {
//			if (isGC) {
//				typeName = "^";
//			}
//			else if (isC) {
//				typeName = "%";
//			}
//			// No change for isPin: stays *
//		}
//		else if ("&".equals(typeName)) {
//			if (isGC) {
//				typeName = "%";
//			}
//			else if (isC) {
//				typeName = "%";
//			}
//			// No change for isPin: stays &
//		}
//		else if (isC && isReferredTo) {
//			typeName = typeName + "%";
//		}
//		if (isConst) {
//			leftBuffer.append(CONST + SPACE);
//		}
//		if (isVolatile) {
//			leftBuffer.append(VOLATILE + SPACE);
//		}
//		if (isBased) {
//			if (basedName == null) { //20150121
//				return "";
//			}
//			leftBuffer.append("__based(" + basedName + ")" + SPACE);
//		}
//		if (isMember) {
//			// TODO: 20160330: it seems that even if qual is parsed, if we are not a pointer
//			//  or reference, then qual should not be emitted (e.g., $CC does not emit qual;
//			//  nor does ?)
//			//       But it is emitted for $$A.
//			// TODO: 20160330: need tests for the cases in the above note.  Moreover, them
//			//  member part seems to come out as follows:
//			//        P    =>  aaa:*
//			//        A    =>  aaa:&
//			//        $$A  =>  aaa:()
//			//             or
//			//        $$A  =>  aaa: fn
//			//        $$B  => no CV mod
//			//		  $$CC => cannot get all to work:
//			// Example:
//			//  "?fn@@3P_Daaa@@A2bbb@@AH$$A_Dccc@@A2ddd@@AHH@Z$$BHP_Dccc@@A2ddd@@AHH@Z@ZA" =>
//			//  "int (__cdecl __based(bbb) aaa::* fn)(int __cdecl __based(ddd) ccc::(int),int,int (__cdecl __based(fff) eee::*)(int)))"
//			// Example:
//			//  "?fn@@3$$A_Daaa@@A2bbb@@AH$$A_Dccc@@A2ddd@@AHH@Z$$BHP_Dccc@@A2ddd@@AHH@Z@ZA" =>
//			//  "int (__cdecl __based(bbb) aaa:: fn)(int __cdecl __based(ddd) ccc::(int),int,int (__cdecl __based(fff) eee::*)(int)))"
//			// Example:
//			//  "?var@@3P5aaa@@2bbb@@HA" => "int const volatile __based(bbb) aaa::* var"
//			// Example:
//			//  "?var@@3$$C5aaa@@2bbb@@HA" => "int const volatile __based(bbb) var"
//			// Interesting... can $$C take array (Y) notation?
//			// Example:
//			//  "?var@@3P5aaa@@2bbb@@Y01HA" =>
//			//  "int (const volatile __based(bbb) aaa::* var)[2]"
//			// Example: "?var@@3$$C5aaa@@2bbb@@Y01HA" => PROBLEM
//			if (qual != null) {
//				if (!"".equals(typeName)) {
//					String qualString = qual.emit();
//					if (!("".equals(qualString))) {
//						leftBuffer.append(qualString + "::");
//					}
//				}
//			}
//		}
//		for (CvPrefix p : prefixList) {
//			switch (p) {
//				case unaligned:
//					leftBuffer.append(UNALIGNED + SPACE);
//					break;
//				default:
//					break;
//			}
//		}
//
//		if (isCliArray) {
//			leftBuffer.append("cli::array<");
//			if (arrayRank > 1) {
//				rightBuffer.append("," + arrayRank + ">^");
//			}
//			else {
//				rightBuffer.append(">^");
//			}
//			typeName = "";
//		}
//
//// 20140903		if (isPinModifier) {
//		if (isPin) { // 20140903
//			leftBuffer.append("cli::pin_ptr<");
//			rightBuffer.append(">");
//			rightBuffer.append(typeName);
//			// typeName = "";
//		}
//
////		leftBuffer.append(leftMod);
//		leftMod.insert(0, leftBuffer);
//
////		rightBuffer.append(rightMod);
//		if (!isCliArray) { // 20140903 test of not CliArray
//			for (CvPrefix p : prefixList) {
//				switch (p) {
//					case ptr64:
//						rightBuffer.append(SPACE + PTR64);
//						break;
//					case restrict:
//						rightBuffer.append(SPACE + RESTRICT);
//						break;
//					default:
//						break;
//				}
//			}
//		}
//		rightMod.append(rightBuffer);
//
//		if (isCLI) {
////		buffer.append(cvMod.emit(typeName.toString(), isReferredTo, leftBuffer.toString(),
////			rightBuffer.toString()));
//			buffer.append(cvMod.emit(typeName.toString(), isReferredTo, leftMod, rightMod));
//		}
//		else {
//			buffer.append(leftBuffer);
//			buffer.append(typeName);
//			if ((buffer.length() != 0) && (rightBuffer.length() != 0) &&
//				(buffer.charAt(buffer.length() - 1) == ' ')) {
//				buffer.deleteCharAt(buffer.length() - 1);
//			}
//			buffer.append(rightBuffer);
//		}
//
//		return buffer.toString();
//	}
//
//	/******************************************************************************/
//	/******************************************************************************/
//	// DO NOT DELETE THE CODE BELOW!!!
//	//  It is work in progress, trying to find the right hierarchical structures
//	//  and output mechanisms that will make everything better.
//	/******************************************************************************/
//	/******************************************************************************/
//
//	private void parse_trying20140619(MDMang dmang) throws MDException {
//		CharacterIteratorAndBuilder iter = dmang.getCharacterIteratorAndBuilder();
//		char ch;
//
////		boolean done = false;
////		char ch = iter.peek();
////		if (ch == '$') {
////			iter.getAndIncrement();
////			ch = iter.getAndIncrement();
////			switch (ch) {
////				case 'B':
////					isData = true;
////					done = true;
//////					throw new MDException("BBBBBBBB");
////					break;
////
////				default: //We haven't seen others yet.
////					iter.previous();
////					iter.previous();
////					break;
////			}
////		}
////		if (done) {
////			return;
////		}
//
//		boolean prefixDone = false;
//		while (!prefixDone) {
//			ch = iter.peek();
//			switch (ch) {
//				case 'E':
//					isPointer64 = true;
//					prefixList.add(CvPrefix.ptr64);
//					iter.getAndIncrement();
//					break;
//				case 'F':
//					isUnaligned = true;
//					prefixList.add(CvPrefix.unaligned);
//					iter.getAndIncrement();
//					break;
//				case 'I':
//					isRestrict = true;
//					prefixList.add(CvPrefix.restrict);
//					iter.getAndIncrement();
//					break;
//				default:
//					prefixDone = true;
//					break;
//			}
//		}
//
//		// Note: Codes E, F, G, and H used to contain "far" and now are different.
//		//       E = "far" ; F = "const far" ; G = "volatile far" ; H = "const volatile far"
//		//       However, E and F are now prefixes; and G and H are grouped with others.
//		//       There is probably historical reason (look into this more?) for, for
//		//       example, C, G, and K to be the same.  Perhaps C was the small memory model,
//		//       G had far pointers, and K was huge????
//		ch = iter.getAndIncrement();
//		switch (ch) {
//			case '$': {
//				isData = true;
////				ch = iter.getAndIncrement();
////				switch (ch) {
////					case 'A':
////						special = "^";
////						isGC = true;
////						isCLI = true;
////						break;
////					case 'B':
////						special = "*";
////						isPin = true;
////						isCLI = true;
////						break;
////					case 'C':
////						special = "%";
////						isC = true;
////						isCLI = true;
////						break;
////					case '0':
////					case '1':
////					case '2':
////					case '3':
////					case '4':
////					case '5':
////					case '6':
////					case '7':
////					case '8':
////					case '9': {
////						special = "^"; // TODO: Not sure
////						isCLI = true;
////						// Two digit number only.  True encoding is hex: 01 - 20 (1 to 32).
////						//  But MSFT undname doesn't decode this
////						// properly (and interprets values > 'F').  To really know... start
////						//  from C-Language source, which I've done.
////						int rank;
////						if (ch >= '0' && ch <= '9') {
////							rank = ch - '0';
////						}
////						else if (ch >= 'A' && ch <= 'F') {
////							rank = ch - 'A' + 10;
////						}
////						else {
////							throw new MDException("invalid cli:array rank");
////						}
////						ch = iter.getAndIncrement();
////						if (ch >= '0' && ch <= '9') {
////							rank = rank * 16 + ch - '0';
////						}
////						else if (ch >= 'A' && ch <= 'F') {
////							rank = rank * 16 + ch - 'A' + 10;
////						}
////						else {
////							throw new MDException("invalid cli:array rank");
////						}
////						isCliArray = true;
////						arrayRank = Integer.toString(rank);
////					}
////						break;
////					default:
////						// Could be others.
////						break;
////				}
//			}
//				iter.previous();
//				break;
//			case 'A':
//				isData = true;
//				break;
//			case 'B':
//			case 'J':
//				isData = true;
//				isConst = true;
//				break;
//			case 'C':
//			case 'G':
//			case 'K':
//				isData = true;
//				isVolatile = true;
//				break;
//			case 'D':
//			case 'H':
//			case 'L':
//				isData = true;
//				isConst = true;
//				isVolatile = true;
//				break;
//			case 'M':
//				isData = true;
//				isBased = true;
//				break;
//			case 'N':
//				isData = true;
//				isConst = true;
//				isBased = true;
//				break;
//			case 'O':
//				isData = true;
//				isVolatile = true;
//				isBased = true;
//				break;
//			case 'P':
//				isData = true;
//				isConst = true;
//				isVolatile = true;
//				isBased = true;
//				break;
//			case 'Q':
//			case 'U':
//			case 'Y':
//				isData = true;
//				isMember = true;
//				break;
//			case 'R':
//			case 'V':
//			case 'Z':
//				isData = true;
//				isConst = true;
//				isMember = true;
//				break;
//			case 'S':
//			case 'W':
//			case '0':
//				isData = true;
//				isVolatile = true;
//				isMember = true;
//				break;
//			case 'T':
//			case 'X':
//			case '1':
//				isData = true;
//				isConst = true;
//				isVolatile = true;
//				isMember = true;
//				break;
//			case '2':
//				isData = true;
//				isBased = true;
//				isMember = true;
//				break;
//			case '3':
//				isData = true;
//				isConst = true;
//				isBased = true;
//				isMember = true;
//				break;
//			case '4':
//				isData = true;
//				isVolatile = true;
//				isBased = true;
//				isMember = true;
//				break;
//			case '5':
//				isData = true;
//				isConst = true;
//				isVolatile = true;
//				isBased = true;
//				isMember = true;
//				break;
//			case '6':
//			case '7':
//				isFunction = true;
//				break;
//			case '8':
//			case '9':
//				isFunction = true;
//				isMember = true;
//				break;
//			case '_':
//				isFunction = true;
//				switch (iter.getAndIncrement()) {
//					case 'A':
//					case 'B':
//						isBased = true;
//						break;
//					case 'C':
//					case 'D':
//						isBased = true;
//						isMember = true;
//						break;
//					default:
//						iter.previous();
//						break;
//				}
//				break;
//			default:
//				iter.previous();
//				break;
//		}
//		if (isCLI) {
//			cvMod = new MDCVModifier(dmang);
//		}
//		if (isMember) {
//			// qual = new MDQualification(dmang);
//			qual = new MDQualification();
//			qual.parse1(dmang);
//			if (isFunction) {
//				cvMod = new MDCVModifier(dmang);
//			}
//		}
//		if (isBased) {
//			switch (iter.getAndIncrement()) {
//				case '0':
//					basedName = "void";
//					break;
//				case '2':
//					// MDQualifiedName qn = new MDQualifiedName(dmang);
//					MDQualifiedName qn = new MDQualifiedName();
//					qn.parse1(dmang);
//					basedName = qn.emit();
//					break;
//				case '5':
//					basedName = "";
//					break;
//				default:
//					basedName = "";
//					return;
//			}
//		}
//	}
//
//	public String emit_new(String typeName, boolean isReferredTo, String leftMod, String rightMod) {
//		StringBuffer buffer = new StringBuffer();
//		StringBuffer rightBuffer = new StringBuffer();
//		StringBuffer leftBuffer = new StringBuffer();
//		// Override typeName if necessary
//		// Note that isGC has different values for * and &
//		if ("*".equals(typeName)) {
//			if (isGC) {
//				typeName = "^";
//			}
//			else if (isC) {
//				typeName = "%";
//			}
//			// No change for isPin: stays *
//		}
//		else if ("&".equals(typeName)) {
//			if (isGC) {
//				typeName = "%";
//			}
//			else if (isC) {
//				typeName = "%";
//			}
//			// No change for isPin: stays &
//		}
//		else if (isC && isReferredTo) {
//			typeName = typeName + "%";
//		}
//		if (isConst) {
//			leftBuffer.append(CONST + SPACE);
////			buffer.append(CONST + SPACE);
//		}
//		if (isVolatile) {
//			leftBuffer.append(VOLATILE + SPACE);
////			buffer.append(VOLATILE + SPACE);
//		}
//
//		if (isBased) {
//			leftBuffer.append("__based(" + basedName + ")" + SPACE);
////			rightBuffer.append("__based(" + basedName + ")" + SPACE);
////			buffer.append("__based(" + basedName + ")" + SPACE);
//		}
//		if (isMember) {
//			if (qual != null) {
//				if (!"".equals(typeName)) {
//					String qualString = qual.emit();
//					if (!("".equals(qualString))) {
//						leftBuffer.append(qualString + "::");
////						rightBuffer.append(qualString + "::");
////						buffer.append(qualString + "::");
//					}
//				}
//			}
//		}
//
//		if (isUnaligned) {
//			leftBuffer.append(UNALIGNED + SPACE);
////			buffer.append(UNALIGNED + SPACE);
////			nameBuffer.append(UNALIGNED + SPACE);
//		}
//
//		leftBuffer.append(leftMod);
//		rightBuffer.append(rightMod);
//
////		StringBuffer nameBuffer = new StringBuffer();
//
////		if (!"".equals(typeName)) {
////			buffer.append(typeName);
//////			nameBuffer.append(typeName);
////		}
//
////		if (isPointer64) {
////			rightBuffer.append(SPACE + PTR64);
////		}
////		if (isRestrict) {
////			rightBuffer.append(SPACE + RESTRICT);
////		}
//		for (CvPrefix p : prefixList) {
//			switch (p) {
//				case ptr64:
//					rightBuffer.append(SPACE + PTR64);
//					break;
//				case restrict:
//					rightBuffer.append(SPACE + RESTRICT);
//					break;
//				default:
//					break;
//			}
//		}
//
////		if (isCLI) {
////			typeName =
////				cvMod.emit(typeName.toString(), isReferredTo, leftBuffer.toString(),
////					rightBuffer.toString());
////		}
//
////		if (cvMod != null) {
//		if (isCLI) {
////		typeName =
////			cvMod.emit(typeName.toString(), isReferredTo, leftBuffer.toString(),
////			rightBuffer.toString());
//			buffer.append(cvMod.emit(typeName.toString(), isReferredTo, new StringBuilder(
//				leftBuffer), new StringBuilder(rightBuffer)));
//		}
//		else {
//			buffer.append(leftBuffer);
//			buffer.append(typeName);
//			if ((buffer.length() != 0) && (rightBuffer.length() != 0) &&
//				(buffer.charAt(buffer.length() - 1) == ' ')) {
//				buffer.deleteCharAt(buffer.length() - 1);
//			}
//			buffer.append(rightBuffer);
//		}
//
////		if (isCLI) {
////			typeName = cvMod.emit(typeName.toString(), isReferredTo);
//////			buffer.append(cvMod.emit(nameBuffer.toString(), isReferredTo));
////		}
////		else {
////			buffer.append(nameBuffer.toString());
////		}
//
////		for (CvPrefix p : prefixList) {
////			switch (p) {
////				case unaligned:
////					buffer.append(UNALIGNED + SPACE);
////					break;
////				default:
////					break;
////			}
////		}
////		if (isCLI) {
////			typeName = cvMod.emit(typeName.toString(), isReferredTo);
////		}
////		if (!"".equals(typeName)) {
////			buffer.append(typeName);
////		}
////		for (CvPrefix p : prefixList) {
////			switch (p) {
////				case ptr64:
////					buffer.append(SPACE + PTR64);
////					break;
////				case restrict:
////					buffer.append(SPACE + RESTRICT);
////					break;
////				default:
////					break;
////			}
////		}
//
////		if ((buffer.length() != 0) && (rightBuffer.length() != 0) &&
////			(buffer.charAt(buffer.length() - 1) == ' ')) {
////			buffer.deleteCharAt(buffer.length() - 1);
////		}
////		buffer.append(rightBuffer);
//		return buffer.toString();
//	}
//
//	public String emit_orig(String typeName, boolean isReferredTo) {
//		StringBuffer buffer = new StringBuffer();
//		StringBuffer rightBuffer = new StringBuffer();
//		// Override typeName if necessary
//		// Note that isGC has different values for * and &
//		if ("*".equals(typeName)) {
//			if (isGC) {
//				typeName = "^";
//			}
//			else if (isC) {
//				typeName = "%";
//			}
//			//No change for isPin: stays *
//		}
//		else if ("&".equals(typeName)) {
//			if (isGC) {
//				typeName = "%";
//			}
//			else if (isC) {
//				typeName = "%";
//			}
//			// No change for isPin: stays &
//		}
//		else if (isC && isReferredTo) {
//			typeName = typeName + "%";
//		}
//		if (isConst) {
//			buffer.append(CONST + SPACE);
//		}
//		if (isVolatile) {
//			buffer.append(VOLATILE + SPACE);
//		}
//		if (isBased) {
//			buffer.append("__based(" + basedName + ")" + SPACE);
//		}
//		if (isMember) {
//			if (qual != null) {
//				if (!"".equals(typeName)) {
//					String qualString = qual.emit();
//					if (!("".equals(qualString))) {
//						buffer.append(qualString + "::");
//					}
//				}
//			}
//		}
//		for (CvPrefix p : prefixList) {
//			switch (p) {
//				case unaligned:
//					buffer.append(UNALIGNED + SPACE);
//					break;
//				default:
//					break;
//			}
//		}
//		if (!"".equals(typeName)) {
//			buffer.append(typeName);
//		}
//		for (CvPrefix p : prefixList) {
//			switch (p) {
//				case ptr64:
//					rightBuffer.append(SPACE + PTR64);
//					break;
//				case restrict:
//					rightBuffer.append(SPACE + RESTRICT);
//					break;
//				default:
//					break;
//			}
//		}
//		if ((buffer.length() != 0) && (rightBuffer.length() != 0) &&
//			(buffer.charAt(buffer.length() - 1) == ' ')) {
//			buffer.deleteCharAt(buffer.length() - 1);
//		}
//		buffer.append(rightBuffer);
//		return buffer.toString();
//	}

}

/******************************************************************************/
/******************************************************************************/
