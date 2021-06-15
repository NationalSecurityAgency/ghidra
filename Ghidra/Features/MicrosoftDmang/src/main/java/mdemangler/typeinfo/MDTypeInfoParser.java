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

/**
 * This class parses the mangled string at the current offset to determine and
 *  create the appropriate type of MDTypeInfo.
 */
public class MDTypeInfoParser {

	// public static MDtype parseExternalType(MDMang) {
	// MDType type = MDDataTypeParser.parse(dmang, false);
	// cvModi = new MDCVMod(getBuilderClass());
	// cvModi.parse1(dmang);
	//
	// }

	/**
	 * This method parses the data sequence to determine the appropriate MDTypeInfo
	 *  to continue parsing.  The method can be recursive, so rttiNum is passed into
	 *  the recursion.
	 * @param dmang The MDMang demangler control.
	 * @param rttiNum The RTTI number currently seen in the processing (-1 if none)
	 * @return The MDTypeInfo created for the data sequence being parsed.
	 * @throws MDException For a host of data-driven parsing reasons.
	 */
	public static MDTypeInfo parse(MDMang dmang, int rttiNum) throws MDException {
		MDTypeInfo typeInfo;
		boolean isBased = false;
		if (dmang.peek() == '_') {
			isBased = true;
			dmang.increment();
		}
		char code = dmang.peek();
		switch (code) {
			case '$': // Special Handling Function:
				dmang.increment();
				typeInfo = parseSpecialHandlingFunction(dmang, rttiNum);
				break;
			case '0':
				dmang.increment();
				typeInfo = new MDVariableInfo(dmang);
				typeInfo.setPrivate();
				typeInfo.setStatic();
				break;
			case '1':
				dmang.increment();
				typeInfo = new MDVariableInfo(dmang);
				typeInfo.setProtected();
				typeInfo.setStatic();
				break;
			case '2':
				dmang.increment();
				typeInfo = new MDVariableInfo(dmang);
				typeInfo.setPublic();
				typeInfo.setStatic();
				break;
			case '3': // Believe this to be "global" data
				dmang.increment();
				typeInfo = new MDVariableInfo(dmang);
				break;
			case '4': // Believe this to be "static local" data
				dmang.increment();
				typeInfo = new MDVariableInfo(dmang);
				break;
			case '5': // Believe this to be "guard" data.
				dmang.increment();
				typeInfo = new MDGuard(dmang);
				break;
			case '6':
				// 20180403: Figured out that this could be a VFTable or an RTTI4; the other
				//  RTTI will show up as case'8'.
				dmang.increment();
				if (rttiNum == 4) {
					typeInfo = new MDRTTI4(dmang);
				}
				else { //should be -1
					typeInfo = new MDVFTable(dmang);
				}
				break;
			case '7':
				// Found on 20140327:
				// "??_7testAccessLevel@@6B@" = "const testAccessLevel::`vftable'"
				// Found on 20140521 (Win7):
				// "??_7CAnalogAudioStream@@6BCUnknown@@CKsSupport@@@", discovered
				// nesting
				// isData = true; //TODO: this is actually data, but not sure of our
				// downstream processing based on this flag. Fix somehow.
				dmang.increment();
				typeInfo = new MDVBTable(dmang);
				break;
			case '8':
				// All but the RTTI except RTT4 seem to show up here
				//  under case '8'; RTTI4 is co-mingled under case '6' with VFTable.
				// TODO: UINFO: metatype (we had isVBTable = true, but I now believe
				// that
				// is wrong).
				// isData = true; //TODO: this is actually data, but not sure of our
				// downstream processing based on this flag. Fix somehow.
				dmang.increment();
				switch (rttiNum) {
					case 0:
						typeInfo = new MDRTTI0(dmang);
						break;
					case 1:
						typeInfo = new MDRTTI1(dmang);
						break;
					case 2:
						typeInfo = new MDRTTI2(dmang);
						break;
					case 3:
						typeInfo = new MDRTTI3(dmang);
						break;
					default: //4 (shouldn't happen) and -1
						typeInfo = new MDTypeInfo(dmang);
						break;
				}
				break;
			case '9': // Believe this to be vcall.
				// dmang.parseInfoPush(1, "VCall access???");
				dmang.increment();
				typeInfo = new MDTypeInfo(dmang);
				// TODO: Not sure if the following are used or not
				// isMember = false; //no reason to have set true
				// hasReturn = false; //no reason to have set true
				// hasArgs = false; //no reason to have set true
				// dmang.parseInfoPop();
				break;
			case 'A':
			case 'B':
				dmang.increment();
				typeInfo = new MDMemberFunctionInfo(dmang);
				typeInfo.setPrivate();
				break;
			case 'C':
			case 'D':
				dmang.increment();
				typeInfo = new MDMemberFunctionInfo(dmang);
				typeInfo.setPrivate();
				typeInfo.setStatic();
				break;
			case 'E':
			case 'F':
				dmang.increment();
				typeInfo = new MDMemberFunctionInfo(dmang);
				typeInfo.setPrivate();
				typeInfo.setVirtual();
				break;
			case 'G':
			case 'H':
				dmang.increment();
				typeInfo = new MDVFAdjustor(dmang);
				typeInfo.setPrivate();
				break;
			case 'I':
			case 'J':
				dmang.increment();
				typeInfo = new MDMemberFunctionInfo(dmang);
				typeInfo.setProtected();
				break;
			case 'K':
			case 'L':
				dmang.increment();
				typeInfo = new MDMemberFunctionInfo(dmang);
				typeInfo.setProtected();
				typeInfo.setStatic();
				break;
			case 'M':
			case 'N':
				dmang.increment();
				typeInfo = new MDMemberFunctionInfo(dmang);
				typeInfo.setProtected();
				typeInfo.setVirtual();
				break;
			case 'O':
			case 'P':
				dmang.increment();
				typeInfo = new MDVFAdjustor(dmang);
				typeInfo.setProtected();
				break;
			case 'Q':
			case 'R':
				dmang.increment();
				typeInfo = new MDMemberFunctionInfo(dmang);
				typeInfo.setPublic();
				break;
			case 'S':
			case 'T':
				dmang.increment();
				typeInfo = new MDMemberFunctionInfo(dmang);
				typeInfo.setPublic();
				typeInfo.setStatic();
				break;
			case 'U':
			case 'V':
				dmang.increment();
				typeInfo = new MDMemberFunctionInfo(dmang);
				typeInfo.setPublic();
				typeInfo.setVirtual();
				break;
			case 'W':
			case 'X':
				dmang.increment();
				typeInfo = new MDVFAdjustor(dmang);
				typeInfo.setPublic();
				break;
			case 'Y':
			case 'Z':
				// These are non-member functions
				dmang.increment();
				typeInfo = new MDFunctionInfo(dmang);
				typeInfo.setNonMember();
				break;
			default: // TODO: Any missing cases?
				// MDMANG SPECIALIZATION USED.
				if (dmang.allowMDTypeInfoParserDefault()) {
					// Partial hack: location of these push/pop method calls.
					// dmang.parseInfoPush(0, "(no access)");
					// No getAndIncrement() here
					// TODO: See if I can eliminate this temporary initialization.
					typeInfo = new MDTypeInfo(dmang);
					// dmang.parseInfoPop();
					break;
				}
				throw new MDException("Invalid MDTypeInfo, unknown case: " + code);
		}
		if (isBased && (typeInfo instanceof MDFunctionInfo)) {
			MDBasedAttribute based = new MDBasedAttribute(dmang);
			based.parse();
			((MDFunctionInfo) typeInfo).setBased(based);
		}
		return typeInfo;
	}

	/**
	 * This method handles MDTypeInfo that begin with the '$' character.  The method is
	 *  a natural place to break the processing to reduce the complexity of the calling
	 *  method's switch statement.
	 * @param dmang The MDMang demangler control.
	 * @param rttiNum The RTTI number currently seen in the processing (-1 if none)
	 * @return The MDTypeInfo created for the data sequence being parsed.
	 * @throws MDException For a host of data-driven parsing reasons.
	 */
	public static MDTypeInfo parseSpecialHandlingFunction(MDMang dmang, int rttiNum)
			throws MDException {
		MDTypeInfo typeInfo;
		char ch = dmang.getAndIncrement();
		switch (ch) {
			// UINFO: (0-5) isFunction, isMember, isvtordisp (0-5)
			// UINFO: val%2==0: near; val%2==0: far;
			case '0':
			case '1':
				typeInfo = new MDVtordisp(dmang);
				typeInfo.setPrivate();
				break;
			case '2':
			case '3':
				typeInfo = new MDVtordisp(dmang);
				typeInfo.setProtected();
				break;
			case '4':
			case '5':
				typeInfo = new MDVtordisp(dmang);
				typeInfo.setPublic();
				break;
			case '$':
				char ch2 = dmang.getAndIncrement();
				switch (ch2) {
					case 'J':
					case 'N':
					case 'O':
					// TODO: we have J, N, O--not sure which is which:
					// UINFO: CManagedILFunction
					// UINFO: CManagedILDLLImportData
					// UINFO: CManagedNativeDLLImportData
					{
						//// Skip past '0' through '9' encoding of 0 - 9 additional
						//// characters.
						char c;
						c = dmang.getAndIncrement();
						if (c < '0' || c > '9') {
							throw new MDException(
								"Access Level 'extern \"C\"' count is wrong: " + c);
						}
						int cnt = c - '0';
						while (cnt-- > 0) {
							c = dmang.getAndIncrement();
						}
					}
						typeInfo = MDTypeInfoParser.parse(dmang, rttiNum);
						typeInfo.setExternC();
						break;
					// TODO: we have F, H, Q--not sure which is which:
					// TODO: L and M are also parsed
					// UINFO: CPPManagedILFunction
					// UINFO: CPPManagedILMain
					// UINFO: CPPManagedILDLLImportData
					// UINFO: CPPManagedNativeDLLImportData
					// UINFO: MGD_AppDomain
					case 'F':
					case 'H':
					case 'L':
					case 'M':
					case 'Q':
						typeInfo = MDTypeInfoParser.parse(dmang, rttiNum);
						break;
					default:
						throw new MDException("Access Level $$, unknown case: " + ch2);
				}
				typeInfo.setSpecialHandlingCode(ch2);
				break;
			// TODO: see following UINFO.
			// UINFO:
			// A=localdtor
			// B=vcall()
			// C=vdispmap
			// D=templateStaticDataMemberCtor
			// E=templateStaticDataMemberDtor
			case 'B':
				typeInfo = new MDVCall(dmang);
				break;
			case 'R':
				typeInfo = new MDVtordispex(dmang);
				char ch3 = dmang.getAndIncrement();
				switch (ch3) {
					case '0':
					case '1':
						typeInfo.setPrivate();
						break;
					case '2':
					case '3':
						typeInfo.setProtected();
						break;
					case '4':
					case '5':
						typeInfo.setPublic();
						break;
					default: // TODO: Any missing cases?
						throw new MDException("Access Level $R, unknown case: " + ch3);
				}
				break;
			case 'A': // TODO: see following UINFO.
				// UINFO: localdtor
			case 'C': // TODO: see following UINFO.
				// UINFO: vdispmap
			case 'D': // TODO: see following UINFO.
				// UINFO: templateStaticDataMemberCtor
			case 'E': // TODO: see following UINFO.
				// UINFO: E=templateStaticDataMemberDtor
			default: // TODO: Any missing cases?
				throw new MDException("Access Level $, unknown case: " + ch);
		}
		return typeInfo;
	}
}

/******************************************************************************/
/******************************************************************************/
