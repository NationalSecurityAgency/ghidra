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
/*
 * Created on Jun 12, 2003
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.app.decompiler;

import ghidra.program.model.pcode.*;

/**
 * 
 *
 * A C code token which is not an operation, variable, function name, or type. Like '(' or ','
 * A SyntaxToken may be or may include spacing
 */
public class ClangSyntaxToken extends ClangToken {
	private int open, close;

	public ClangSyntaxToken(ClangNode par) {
		super(par);
		open = close = -1;
	}

	public ClangSyntaxToken(ClangNode par, String txt) {
		super(par, txt);
		open = close = -1;
	}

	public ClangSyntaxToken(ClangNode par, String txt, int color) {
		super(par, txt, color);
		open = close = -1;
	}

	@Override
	public boolean isVariableRef() {
		if (Parent() instanceof ClangVariableDecl) {
			return true;
		}
		return false;
	}

	@Override
	public void decode(Decoder decoder, PcodeFactory pfactory) throws DecoderException {
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == AttributeId.ATTRIB_OPEN.id()) {
				open = (int) decoder.readSignedInteger();
			}
			else if (attribId == AttributeId.ATTRIB_CLOSE.id()) {
				close = (int) decoder.readSignedInteger();
			}
		}
		decoder.rewindAttributes();
		super.decode(decoder, pfactory);
	}

	public int getOpen() {
		return open;
	}

	public int getClose() {
		return close;
	}
}
