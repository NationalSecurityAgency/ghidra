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
package mdemangler.naming;

import mdemangler.*;

/**
 * This class represents one component of a namespace qualification (see
 * MDQualification).
 */
public class MDQualifier extends MDParsableItem {
	private static final String ANONYMOUS_NAMESPACE = "`anonymous namespace'";
	private static final String UNKNOWN_NAMESPACE = "MDMANG_UNK_QUALIFICATION";
	private MDReusableName name;
	private MDReusableName nameAnonymous;
	private MDReusableName nameInterface;
	private MDNestedName nameNested;
	private MDNumberedNamespace nameNumbered;
	private String nameQ;
	private String nameC; // Windows 10 stuff

	public MDQualifier(MDMang dmang) {
		super(dmang);
	}

	public boolean isInterface() {
		return (nameInterface != null);
	}

	public boolean isNested() {
		return (nameNested != null);
	}

	public MDNestedName getNested() {
		return nameNested;
	}

	@Override
	public void insert(StringBuilder builder) {
		// Only one of these will hit.
		if (name != null) {
			name.insert(builder);
		}
		else if (nameAnonymous != null) {
			dmang.insertString(builder, ANONYMOUS_NAMESPACE);
		}
		else if (nameInterface != null) {
			nameInterface.insert(builder);
		}
		else if (nameNested != null) {
			nameNested.insert(builder);
		}
		else if (nameNumbered != null) {
			nameNumbered.insert(builder);
		}
		else if (nameQ != null) {
			dmang.insertString(builder, nameQ);
		}
		else if (nameC != null) {
			dmang.insertString(builder, nameC);
		}
		else {
			dmang.insertString(builder, UNKNOWN_NAMESPACE);
		}
	}

	@Override
	protected void parseInternal() throws MDException {
		if (dmang.peek() == '?') {
			switch (dmang.peek(1)) {
				case '?':
					nameNested = new MDNestedName(dmang);
					nameNested.parse();
					break;
				case '$':
					// This is a template, but it will get processed through MDReusableName.
					name = new MDReusableName(dmang);
					name.parse();
					break;
				case 'A': // Anonymous namespace
					// 20140522 found that we should Keep the 'A' as part of the name
					//  (found in a backreferrence to the name), so do not do dmang.increment().
					dmang.parseInfoPush(0, "FragmentName from Anonymous Namespace");
					dmang.increment(); // skip the '?'
					nameAnonymous = new MDReusableName(dmang);
					nameAnonymous.parse();
					dmang.parseInfoPop();
					break;
				case 'I': // Believe this is interface namespace 
					// 20140522: See note for 'A' anonymous namespace; for 'I' there is no
					// evidence to include the 'I' in the fragment (investigation seems to have
					// it removed).
					dmang.parseInfoPush(0, "InterfaceName from NameFragment");
					dmang.increment(); // skip the '?'
					dmang.increment(); // skip the 'I'
					nameInterface = new MDReusableName(dmang);
					nameInterface.parse();
					dmang.parseInfoPop();
					break;
				case 'C':
					// Windows 10 seems to have "?C" that we don't know how to process.
					//  Best guess at the moment is to read an MDNameFragment next and
					//  keep the fragment's terminating '@'.  'C' used to be part of the
					//  NumberedNamespace below.
					// MDMANG SPECIALIZATION USED.
					if (dmang.processQualCAsSpecialFragment()) {
						dmang.parseInfoPush(0, "NameC");
						dmang.increment(); // skip the '?'
						dmang.increment(); // skip the 'C'
						MDFragmentName fragName = new MDFragmentName(dmang);
						fragName.keepTerminator(); // keeps the terminating '@'
						fragName.parse();
						nameC = fragName.toString();
						dmang.parseInfoPop();
						break;
					}
					// else fall through to MDNumberedNamespace below.
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
					// Whether or not intended (I don't think it was), for the cases other
					//  than those that begin with 'A' or 'I', undname processes all of
					//  these as numbered namespaces.  'A' would normally be 0, but 'I'
					//  could be the beginning of a host of numbered namespaces.
				case 'B':
					// See the possible "case 'C'" above, which fixes other issues, but makes
					//  long test go from 73 to 1308 wrong.
//				case 'C':
				case 'D':
				case 'E':
				case 'F':
				case 'G':
				case 'H':
				case 'J':
				case 'K':
				case 'L':
				case 'M':
				case 'N':
				case 'O':
				case 'P':
					dmang.increment(); // skip the '?'
					nameNumbered = new MDNumberedNamespace(dmang);
					nameNumbered.parse();
					break;
				case 'Q':
					// 20160729 Win10 stuff:
					//  "?__abi_GetIids@?QObject@Platform@@?$Array@P$AAVString@Platform@@$00@2@U$AAGJPAKPAPAVGuid@2@@Z_10006bc0";
					// 20170331: Also seen in this symbol:
					//  "?add@?Q?$IObservableMap@HH@Collections@Foundation@Windows@@MapChanged@?$Map@HHU?$less@H@std@@@2Platform@@UE$AAA?AVEventRegistrationToken@34@PE$AAV?$MapChangedEventHandler@HH@234@@Z"
					dmang.parseInfoPush(0, "InterfaceName from QualifiedName");
					dmang.increment(); // skip the '?'
					dmang.increment(); // skip the 'Q'
					MDQualification qualName = new MDQualification(dmang);
					qualName.parse();
					StringBuilder nameQBuilder = new StringBuilder();
					qualName.insert(nameQBuilder);
					dmang.insertString(nameQBuilder, "[");
					dmang.appendString(nameQBuilder, "]");
					nameQ = nameQBuilder.toString();
					dmang.parseInfoPop();
					break;
				default: // special name
					throw new MDException("SpecialName not expected in qualification list");
			}
		}
		else {
			name = new MDReusableName(dmang);
			name.parse();
		}
	}
}

/******************************************************************************/
/******************************************************************************/
