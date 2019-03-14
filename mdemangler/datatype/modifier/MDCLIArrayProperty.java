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
 * This class represents a CLI Array managed property of a modifier type within a Microsoft
 * mangled symbol.
 */
public class MDCLIArrayProperty extends MDManagedProperty {
//	private static final String prefixEmitClause = "cli::array<";
//	private static final String intermediateEmitClause = ",";
//	private static final String suffixEmitClause = ">^";
//	private int arrayRank;
//
	public MDCLIArrayProperty(MDMang dmang) {
		super(dmang);
	}

//	public MDCLIArrayProperty(String modifierTypeName, MDMang dmang)
//			throws MDException {
//		super(modifierTypeName, dmang);
//		parse(dmang);
//	}
//
//	@Override
//	void parseCVMod(MDMang dmang) throws MDException {
//		//Doing what we think MSFT is doing: reading and ignoring one character (such as a
//		//  simple CV of A, B, C, D); extra characters in a mangled symbol just cause problems,
//		//  but one read and ignored character is what MSFT is seemingly doing.
//		CharacterIteratorAndBuilder iter = dmang.getCharacterIteratorAndBuilder();
//		iter.getAndIncrement();
//	}
//
//	private void parse(MDMang dmang) throws MDException {
//		CharacterIteratorAndBuilder iter = dmang.getCharacterIteratorAndBuilder();
//		//Two digit number only.  True encoding is hex: 01 - 20 (1 to 32).  But MSFT undname
//		// doesn't decode this properly (and interprets values > 'F').  To really know...
//		// start from C-Language source, which I've done.
//		char ch = iter.getAndIncrement();
//		if (ch >= '0' && ch <= '9') {
//			arrayRank = ch - '0';
//		}
//		else if (ch >= 'A' && ch <= 'F') {
//			arrayRank = ch - 'A' + 10;
//		}
//		else {
//			throw new MDException("invalid cli:array rank");
//		}
//		ch = iter.getAndIncrement();
//		if (ch >= '0' && ch <= '9') {
//			arrayRank = arrayRank * 16 + ch - '0';
//		}
//		else if (ch >= 'A' && ch <= 'F') {
//			arrayRank = arrayRank * 16 + ch - 'A' + 10;
//		}
//		else {
//			throw new MDException("invalid cli:array rank");
//		}
//		//TODO: might remove the following line... char might be an ignored cvmod, to be
//		//  parsed outside of this object
//		//Skip next character (seems it can be any character, except possibly '$')
//		iter.getAndIncrement();
//	}
//
//	@Override
//	public void insert(StringBuilder builder) {
//		builder.insertString(prefixEmitClause);
//		if (arrayRank > 1) {
//			builder.appendString(intermediateEmitClause);
//			builder.appendString(Integer.toString(arrayRank));
//		}
//		builder.appendString(suffixEmitClause);
//	}
//
//	@Override
//	public String emit(StringBuilder builder) {
//		builder.insert(0, prefixEmitClause);
//		if (arrayRank > 1) {
//			builder.append(intermediateEmitClause);
//			builder.append(arrayRank);
//		}
//		builder.append(suffixEmitClause);
////		typeName = "";
//		return builder.toString();
//	}
}

/******************************************************************************/
/******************************************************************************/
