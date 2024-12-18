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

import mdemangler.MDException;
import mdemangler.MDMang;
import mdemangler.datatype.MDDataType;
import mdemangler.datatype.MDDataTypeParser;

/**
 * This class represents a modifier data type coded with a question mark within a Microsoft mangled
 *  symbol.
 */
public class MDQuestionModifierType extends MDModifierType {

	// TODO: Decide on whether parsing this suffix belongs here... from PDB namespace investigation,
	//  it is reasoned that this suffix identifies an anonymous namespace.  See comments in
	//  MDMangUtils.createStandardAnonymousNamespaceNode(String anon) method.
	private String suffix;

	public MDQuestionModifierType(MDMang dmang) {
		super(dmang);
		cvMod.setQuestionType();
	}

	@Override
	protected void parseInternal() throws MDException {
		super.parseInternal();
		// Let's try to absorb the '`' suffix here (from certain llvm mangled type names) of
		//  form "`fedcba98" where there are 8 zero-padded hex digits after a back tick.
		parseSuffix();
	}

	/**
	 * Returns a possible suffix
	 * @return the suffix or {@code null}
	 */
	public String getSuffix() {
		return suffix;
	}

	private void parseSuffix() {
		if (dmang.peek() == '`') {
			// TODO: when we know what this is and where it belongs, we should consider making
			//  it another MDParsableItem that includes the push/pop on processing so we
			//  can see the capture of the suffix in MDParseInfo.
			int baseLoc = dmang.getIndex();
			StringBuilder builder = new StringBuilder();
			builder.append(dmang.getAndIncrement());
			for (int i = 0; i < 8; i++) {
				if (dmang.done()) {
					// failed to get all characters for the suffix; set the index back and leave
					dmang.setIndex(baseLoc);
					return;
				}
				char c = dmang.getAndIncrement();
				if (!isHexDigit(c)) {
					dmang.setIndex(baseLoc);
					return;
				}
				builder.append(c);
			}
			suffix = builder.toString();
		}
	}

	private static boolean isHexDigit(char c) {
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
	}

	@Override
	protected MDDataType parseReferencedType() throws MDException {
		return MDDataTypeParser.parsePrimaryDataType(dmang, false);
	}
}
