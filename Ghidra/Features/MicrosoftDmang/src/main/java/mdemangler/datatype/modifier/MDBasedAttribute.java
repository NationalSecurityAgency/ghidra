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
import mdemangler.naming.MDBasicName;
import mdemangler.naming.MDQualifiedName;

// ***********NOTE: For "based5 bug" or "basedptr"**************
//
// Any modifier type that has a case '5' (representing that the
// Modifier location is based on a a pointer location ("basedptr")
// is currently invalid in the Microsoft model.  There is a bug
// (my words for it) where it seem that in this case, the notation
// of an invalid option here is noted with a null character ('\0')
// put into the string, but then Microsoft continues to process
// the mangled string.  Any time there is a C/C++ string (array
// of characters) that has a null character in it, this indicates
// the end of the string, even if the full array has more characters
// this is different than in java, in which case the String length
// case meaning and the null character does not.  So if, vis the
// action of inserting and appending mangled substrings, we end
// up with a null character in the java String, we need to truncate
// that String at the appropriate time in the processing of
// outputting a demangled String.  So, we first, purposefully
// insert this null character, and later look for it in order
// to properly truncate the substring in question, in order to 
// mimic what we believe is happening in Microsoft demangler
// code.... but this is true only if we care to mimic Microsoft
// code, which we do and do not want to do, depending on which
// MDMang derivative demangler we are running.  So, watch for
// calls in other classes that peform the dmang.cleanOutput()
// method.

/**
 * This class represents a based property of a modifier type within a Microsoft
 * mangled symbol.
 */
public class MDBasedAttribute extends MDParsableItem {
	private static final String prefixEmitClauseBased = "__based(";
	private static final String suffixEmitClauseBased = ")";

	private String basedName;
	boolean basedPtrBased;
	boolean parsed = false;

	public MDBasedAttribute(MDMang dmang) {
		super(dmang);
	}

	public boolean isBasedPtrBased() {
		return basedPtrBased;
	}

	@Override
	protected void parseInternal() throws MDException {
		parsed = true;
		// TODO: Provide mechanism to turn on/off (move this boolean into MDMang?)
		boolean boolean32BitSymbols = true;
		if (boolean32BitSymbols) {
			switch (dmang.getAndIncrement()) {
				case '0': // UINFO: void
					basedName = "void";
					break;
				case '2': // UINFO: nearptr
					MDQualifiedName qn = new MDQualifiedName(dmang);
					qn.parse();
					StringBuilder qnBuilder = new StringBuilder();
					qn.insert(qnBuilder);
					basedName = qnBuilder.toString();
					break;
				case '5': // UINFO: basedptr (reserved: based on basedptr)--should "fail"
					basedPtrBased = true;
					// basedName = " ";
					basedName = null;
					break;
				case MDMang.DONE:
					throw new MDException("Missing based value.");
				default:
					basedName = "";
					return;
			}
		}
		else {
			switch (dmang.getAndIncrement()) {
				case '0': // UINFO: void
					basedName = "void";
					break;
				case '1': // UINFO: self
					basedName = "__self";
					break;
				case '2': // UINFO: nearptr
					basedName = "NYI:__near*";
					break;
				case '3': // UINFO: farptr
					basedName = "NYI:__far*";
					break;
				case '4': // UINFO: hugeptr
					basedName = "NYI:__huge*";
					break;
				case '5': // UINFO: basedptr (reserved: based on basedptr)
					basedPtrBased = true;
					basedName = null;
					// basedName = null;
					break;
				case '6': // UINFO: segment
					basedName = "NYI:__segment";
					break;
				case '7': // UINFO: segname
					MDBasicName bn = new MDBasicName(dmang);
					bn.parse();
					StringBuilder bnBuilder = new StringBuilder();
					bn.insert(bnBuilder);
					dmang.appendString(bnBuilder, "\"");
					dmang.insertString(bnBuilder, "__segmname(\"");
					basedName = bnBuilder.toString();
					break;
				case '8': // UINFO: segaddr
					basedName = "NYI:<segment-address-of-variable>";
					break;
				case MDMang.DONE:
					throw new MDException("Missing based value.");
				default:
					basedName = "";
					return;
			}
		}
	}

	@Override
	public void insert(StringBuilder builder) {
		if (!parsed) {
			return;
		}
		if (basedPtrBased) {
			builder.setLength(0);
			builder.append('\0');
			return;
		}
		dmang.insertSpacedString(builder, suffixEmitClauseBased);
		dmang.insertString(builder, basedName);
		dmang.insertString(builder, prefixEmitClauseBased);
	}

	@Override
	public void append(StringBuilder builder) {
		if (!parsed) {
			return;
		}
		if (basedPtrBased) {
			builder.setLength(0);
			builder.append('\0');
			return;
		}
		dmang.appendString(builder, " ");
		dmang.appendString(builder, prefixEmitClauseBased);
		dmang.appendString(builder, basedName);
		dmang.appendString(builder, suffixEmitClauseBased);
	}
}
