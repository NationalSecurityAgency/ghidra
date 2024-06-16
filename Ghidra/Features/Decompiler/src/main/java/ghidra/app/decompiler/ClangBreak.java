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
package ghidra.app.decompiler;

import ghidra.program.model.pcode.*;

/**
 * A line break in source code plus the indenting for the following line.
 */
public class ClangBreak extends ClangToken {

	private int indent;		// Number of characters of indent

	public ClangBreak(ClangNode par) {
		super(par);
		indent = 0;
	}

	public ClangBreak(ClangNode par, int indent) {
		super(par);
		this.indent = indent;
	}

	/**
	 * @return the number of indent levels following this line break
	 */
	public int getIndent() {
		return indent;
	}

	@Override
	public void decode(Decoder decoder, PcodeFactory pfactory) throws DecoderException {
		indent = (int) decoder.readSignedInteger(AttributeId.ATTRIB_INDENT);
		setText("");
	}
}
