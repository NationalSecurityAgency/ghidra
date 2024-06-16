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
package mdemangler.functiontype;

import mdemangler.*;

/**
 * This class represents a calling convention of a function within a Microsoft mangled symbol.
 */
public class MDCallingConvention extends MDParsableItem {
	private String convention;
	// "exported" could also imply __saveregs (from google.doc documentation found, so might
	//  help with this when we use it)
	private boolean exported;

	// According to MSFT:
	// To export functions, the __declspec(dllexport0 keyword must appear to the left of the
	//  calling-convention keyword, if a keyword is specified.  For example:
	//   __declspec(dllexport) void __cdecl Function1(void);
	// To export all of the public data members and member functions in a class, the keyword
	//  must appear to the left of the class name as follows:
	//   class __declspec(dllexport) CExampleExport : public CObject
	//   { ... class definition ...};

	public MDCallingConvention(MDMang dmang) {
		super(dmang);
	}

	public boolean isExported() {
		return exported;
	}

	@Override
	protected void parseInternal() throws MDException {
		char ch = dmang.getAndIncrement();
		// Not exported if A, C, E, G,...; exported if B, D, F, H,...
		exported = (((ch - 'A') % 2) == 1);
		// TODO: 20140422:  Found document at
		//  http://vgce.googlecode.com/svn-history/r238/trunk/docs/nameDecoration.txt
		// that has some interpretations that indicate that the second of each of these
		//  (e.g. B vs. A) also has "__saveregs" as part of the convention.  For 'A' it has
		//  "__cdecl" and for 'B' it has "__cdecl __saveregs" so, perhaps, these really do
		//  have __saveregs, but it is not displayed.  We should investigate creating code
		//  for each (if we can) that looking at the disassembly to see if they have this
		//  difference.  These are on B, D, F, H, J, and L.
		switch (ch) {
			case 'A':
			case 'B':
				// TODO: consider showing exported or not on all of these.
				dmang.parseInfoPush(1, "__cdecl");
				convention = "__cdecl";
				dmang.parseInfoPop();
				break;
			case 'C':
			case 'D':
				dmang.parseInfoPush(1, "__pascal");
				convention = "__pascal";
				dmang.parseInfoPop();
				break;
			case 'E':
			case 'F':
				dmang.parseInfoPush(1, "__thiscall");
				convention = "__thiscall";
				dmang.parseInfoPop();
				break;
			case 'G':
			case 'H':
				dmang.parseInfoPush(1, "__stdcall");
				convention = "__stdcall";
				dmang.parseInfoPop();
				break;
			case 'I':
			case 'J':
				dmang.parseInfoPush(1, "__fastcall");
				convention = "__fastcall";
				dmang.parseInfoPop();
				break;
			case 'K':
			case 'L':
				dmang.parseInfoPush(1, "(KL blank convention)");
				convention = "";
				dmang.parseInfoPop();
				break;
			case 'M':
			case 'N':
				dmang.parseInfoPush(1, "__clrcall");
				convention = "__clrcall";
				dmang.parseInfoPop();
				break;
			case 'O':
			case 'P':
				dmang.parseInfoPush(1, "__eabi");
				convention = "__eabi";
				dmang.parseInfoPop();
				break;
			case 'Q':
			case 'R':
				dmang.parseInfoPush(1, "__vectorcall");
				convention = "__vectorcall";
				dmang.parseInfoPop();
				break;
			case 'S':
			case 'T':
				// MSFT is as shown
				// LLVM is "__attribute__((__swiftcall__))" for code S and blank for T
				dmang.parseInfoPush(1, "__swift_1");
				convention = "__swift_1";
				dmang.parseInfoPop();
				break;
			case 'U':
			case 'V':
				// MSFT is as shown for U, but blank for V
				// LLVM is blank for both
				dmang.parseInfoPush(1, "__swift_2");
				convention = "__swift_2";
				dmang.parseInfoPop();
				break;
			case 'W':
			case 'X':
				// MSFT is blank
				// LLVM is "__attribute__((__swiftasynccall__))" for code W and blank for X
				dmang.parseInfoPush(1, "__swiftasynccall");
				convention = "__swiftasynccall"; // we made up... maybe MSFT will do an _1 suffix?
				dmang.parseInfoPop();
				break;
			case 'Y':
			case 'Z':
				dmang.parseInfoPush(1, "(YZ blank convention)");
				convention = "";
				dmang.parseInfoPop();
				break;
			default:
				throw new MDException("Unknown calling convention " + ch + "\n");
		}
	}

	@Override
	public void insert(StringBuilder builder) {
		dmang.insertString(builder, convention);
		// not used for now...we can consider if this should be emitted later (via some option?)
		// "__dll export" or similar (TODO: find out what we get through code example)
	}
}

/******************************************************************************/
/******************************************************************************/
