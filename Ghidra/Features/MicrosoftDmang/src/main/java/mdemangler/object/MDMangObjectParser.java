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
package mdemangler.object;

import mdemangler.*;
import mdemangler.datatype.MDDataTypeParser;
import mdemangler.template.MDTemplateNameAndArguments;

/**
 * This class parses the mangled string at the current offset to determine and
 *  create the appropriate type of <b><code>MDObject</code></b>.
 */
public class MDMangObjectParser {

	public static MDParsableItem parse(MDMang dmang) throws MDException {
		MDParsableItem item;
		if (dmang.peek() == '?') {
			if (dmang.peek(1) == '@') {
				item = new MDObjectCodeView(dmang);
			}
			else if (dmang.peek(1) == '$') {
				item = new MDTemplateNameAndArguments(dmang);
			}
			else {
				item = new MDObjectCPP(dmang);
			}
		}
		else if ((dmang.peek() == '_') &&
			((dmang.peek(1) == '_') || ((dmang.peek(1) >= 'A') && (dmang.peek(1) <= 'Z')))) {
			item = parseObjectReserved(dmang);
		}
		else if (dmang.peek() == '.') {
			dmang.increment();
			item = MDDataTypeParser.parseDataType(dmang, false);
		}
		else {
			item = new MDObjectC(dmang);
		}
		return item;
	}

	// Thus far, we have seen (created from forward code example):
	//  __mep => [MEP], which is presumably "Managed Entry Point"
	//  __t2m => [T2M], which is presumably "Transition to Managed (code)"
	// Other double underscore values, seen internal to symbols (which we are not sure about
	//  whether comes back to this code):
	// ____abi
	// __mpnHeap
	// __pParameter_m
	// We have seen other examples (in our compiled jan_gray code) that show up in the
	// symbols, but dumpbin does not give a demangled output for them.  In both of these,
	// we currently let the first '$' be part of the bracketed string (our fragment reader
	// allows this character in a fragment at this time, but this could change and the '$'
	// might need to be a flag of some sort.  One of these symbols has another '$' prior to
	// a number (which seems to show overloading of the method--we have actually seen "$0"
	// and "$1" suffixes:
	//  mangled = "__ehhandler$?test_except_f@@YAXH@Z";
	//  msTruth = "[EHHANDLER$] void __cdecl test_except_f(int)";
	//  mangled = "__undwindfunclet$?test_except_f@@YAXH@Z$1";
	//  msTruth = "[UNDWINDFUNCLET$][1] void __cdecl test_except_f(int)";
	//  We crafted a representation for these symbols that have no real truth to compare to.
	//Following are some that are not reported by dumpbin, so no msTruth.  Again, we are
	// making up our own answers.
	//Interestingly, the 64-bit version of gray.exe
	// only has one underscore in the beginning.  How do we reconcile this.  Perhaps these
	// are much different than the __MEP and __T2M prefixes that we see from dumpbin.
	//  mangled = "__TI1?AUX@@";
	//  mdTruth = "[TI1] AUX";
	//  mangled = "__CTA1?AUX@@";
	//  mdTruth = "[CT] AUX";
	//  mangled = "__CT??_R0?AUX@@@81"; //We can get the next line if we ignore that last character '1'
	//  mdTruth = "[CT] struct X `RTTI Type Descriptor'";
	/**
	 * Parses the input data for "Compiler-Reserved" symbols.  The C++/C-specification says that
	 *  symbols that begin with two underscores or with a single underscore followed by a
	 *  capital letter are reserved for compiler use.  These are generally symbols that the
	 *  compiler has generated for code that it generates to fulfill certain needs such as code
	 *  for C++ internals or exception-handling internals.  This method creates our idea of what
	 *  the underlying object is that is named by this compiler-reserved symbol.
	 * @param dmang The <b><code>MDMang</code></b> worker for demangling.
	 * @return MDParsableItem object representing the underlying object that is named
	 *  by the compiler-reserved symbol.
	 * @throws MDException Upon <b><code>MDMang</code></b> parsing issues that cause us to fail
	 *  processing.
	 */
	public static MDParsableItem parseObjectReserved(MDMang dmang) throws MDException {
		MDParsableItem item;
		if (dmang.positionStartsWith("__TI")) {
			dmang.increment("__TI".length());
			item = new MDObjectThrowInfo(dmang);
		}
		//Single underscore version is seen in 64-bit binaries
		else if (dmang.positionStartsWith("_TI")) {
			dmang.increment("_TI".length());
			item = new MDObjectThrowInfo(dmang);
		}
		//__CTA must come before __CT prefix case
		else if (dmang.positionStartsWith("__CTA")) {
			dmang.increment("__CTA".length());
			item = new MDObjectCatchableTypeArray(dmang);
		}
		else if (dmang.positionStartsWith("__CT")) {
			dmang.increment("__CT".length());
			item = new MDObjectCatchableType(dmang);
		}
		//_CTA must come before _CT prefix case
		//Single underscore version is seen in 64-bit binaries
		else if (dmang.positionStartsWith("_CTA")) {
			dmang.increment("_CTA".length());
			item = new MDObjectCatchableTypeArray(dmang);
		}
		//Single underscore version is seen in 64-bit binaries
		else if (dmang.positionStartsWith("_CT")) {
			dmang.increment("_CT".length());
			item = new MDObjectCatchableType(dmang);
		}
		else if (dmang.positionStartsWith("__catch$")) {
			dmang.increment("__catch$".length());
			item = new MDObjectCatch(dmang);
		}
		else if (dmang.positionStartsWith("__catchsym$")) {
			dmang.increment("__catchsym$".length());
			item = new MDObjectCatchSym(dmang);
		}
		else if (dmang.positionStartsWith("__unwindfunclet$")) {
			dmang.increment("__unwindfunclet$".length());
			item = new MDObjectUnwindFunclet(dmang);
		}
		else if (dmang.positionStartsWith("__tryblocktable$")) {
			dmang.increment("__tryblocktable$".length());
			item = new MDObjectTryBlockTable(dmang);
		}
		else if (dmang.positionStartsWith("__unwindtable$")) {
			dmang.increment("__unwindtable$".length());
			item = new MDObjectUnwindTable(dmang);
		}
		else if (dmang.positionStartsWith("__ehhandler$")) {
			dmang.increment("__ehhandler$".length());
			item = new MDObjectEHHandler(dmang);
		}
		else if (dmang.positionStartsWith("__m2mep@")) {
			//dmang.increment("__m2mep@".length());
			//See source8P
			item = new MDObjectBracket(dmang);
		}
		else if (dmang.positionStartsWith("__mep@")) {
			//dmang.increment("__mep@".length());
			//Managed Entry Point
			item = new MDObjectBracket(dmang);
		}
		else if (dmang.positionStartsWith("__t2m@")) {
			//dmang.increment("__t2m@".length());
			//Transition-to-Managed
			item = new MDObjectBracket(dmang);
		}
		else if (dmang.positionStartsWith("__unep@")) {
			//dmang.increment("__unep@".length());
			//See source8P
			item = new MDObjectBracket(dmang);
		}
		else {
			//What else?
			/*See cn3:
				___iob_func
				@__security_check_cookie@4
				__CxxThrowException@8
				___CxxFrameHandler3
				__imp__InitOnceExecuteOnce@16
				__real@00000000
				__real@0000000000000000
				__real@3f1a36e2eb1c432d
			*/
			item = new MDObjectReserved(dmang);
		}
		return item;
	}

	/******************************************************************************/

	/******************************************************************************/
	// DO NOT DELETE THE CODE BELOW!!!
	//  It is work in progress, trying to find the right hierarchical structures
	//  and output mechanisms that will make everything better.
	//  ...especially for the '???' nesting.
	/******************************************************************************/
	/******************************************************************************/

//	private void parseOptionalContexts(MDMang dmang) throws MDException {
//		while (dmang.peek() == '?' && dmang.peek(1) == '?') {
//			dmang.getAndIncrement();
//			//TODO: removed to clean up dmang, but would need an appropriate substitute we
//			//  we intend to use parseOptionalContexts():   dmang.pushContext();
//			parseOptionalContexts(dmang);
//			dmang.popContext();
//		}
//		//qualifiedName = new MDQualifiedName(dmang);
//		qualifiedName = new MDQualifiedName();
//		qualifiedName.parse1(dmang);
//		//typeInfo = new MDTypeInfo(dmang);
//		typeInfo = new MDTypeInfo();
//		typeInfo.parse1(dmang);
//	}
}

/******************************************************************************/
/******************************************************************************/
