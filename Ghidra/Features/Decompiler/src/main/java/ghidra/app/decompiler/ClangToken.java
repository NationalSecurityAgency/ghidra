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

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.awt.Color;
import java.util.List;

//import ghidra.app.plugin.core.decompile.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.*;

/**
 * 
 *
 * Class representing a C code language token
 * May contain links back to pcode object
 */
public class ClangToken implements ClangNode {
	public final static int KEYWORD_COLOR = 0;	// Constants must match Decompiler syntax_highlight
	public final static int COMMENT_COLOR = 1;
	public final static int TYPE_COLOR = 2;
	public final static int FUNCTION_COLOR = 3;
	public final static int VARIABLE_COLOR = 4;
	public final static int CONST_COLOR = 5;
	public final static int PARAMETER_COLOR = 6;
	public final static int GLOBAL_COLOR = 7;
	public final static int DEFAULT_COLOR = 8;
	public final static int ERROR_COLOR = 9;
	public final static int SPECIAL_COLOR = 10;
	public final static int MAX_COLOR = 11;

	private ClangNode parent;
	private ClangLine lineparent;
	private String text;
	private int syntax_type;
	private Color highlight; // Color to highlight with or null if no highlight
	private boolean matchingToken;

	public ClangToken(ClangNode par) {
		parent = par;
		text = null;
		highlight = null;
		syntax_type = DEFAULT_COLOR;
		lineparent = null;
	}

	public ClangToken(ClangNode par, String txt) {
		parent = par;
		text = txt;
		highlight = null;
		syntax_type = DEFAULT_COLOR;
	}

	public ClangToken(ClangNode par, String txt, int color) {
		parent = par;
		text = txt;
		highlight = null;
		syntax_type = color;
	}

	@Override
	public ClangNode Parent() {
		return parent;
	}

	public ClangLine getLineParent() {
		return lineparent;
	}

	public void setLineParent(ClangLine line) {
		lineparent = line;
	}

	@Override
	public Address getMinAddress() {
		return null;
	}

	@Override
	public Address getMaxAddress() {
		return null;
	}

	@Override
	public int numChildren() {
		return 0;
	}

	@Override
	public ClangNode Child(int i) {
		return null;
	}

	@Override
	public ClangFunction getClangFunction() {
		if (parent != null) {
			return parent.getClangFunction();
		}
		return null;
	}

	@Override
	public void setHighlight(Color val) {
		highlight = val;
	}

	public Color getHighlight() {
		return highlight;
	}

	public void setMatchingToken(boolean matchingToken) {
		this.matchingToken = matchingToken;
	}

	public boolean isMatchingToken() {
		return matchingToken;
	}

	public boolean isVariableRef() {
		return false;
	}

	public int getSyntaxType() {
		return syntax_type;
	}

	void setSyntaxType(int syntax_type) {
		this.syntax_type = syntax_type;
	}

	public String getText() {
		return text;
	}

	void setText(String text) {
		this.text = text;
	}

	public void decode(Decoder decoder, PcodeFactory pfactory) throws DecoderException {
		syntax_type = DEFAULT_COLOR;
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == ATTRIB_COLOR.id()) {
				syntax_type = (int) decoder.readUnsignedInteger();
				break;
			}
		}
		text = decoder.readString(ATTRIB_CONTENT);
		if (syntax_type < 0 || syntax_type >= MAX_COLOR) {
			syntax_type = DEFAULT_COLOR;
		}
	}

	@Override
	public void flatten(List<ClangNode> list) {
		list.add(this);
	}

	static public ClangToken buildToken(int node, ClangNode par, Decoder decoder,
			PcodeFactory pfactory) throws DecoderException {
		ClangToken token = null;
		if (node == ELEM_VARIABLE.id()) {
			token = new ClangVariableToken(par);
		}
		else if (node == ELEM_OP.id()) {
			token = new ClangOpToken(par);
		}
		else if (node == ELEM_SYNTAX.id()) {
			token = new ClangSyntaxToken(par);
		}
		else if (node == ELEM_BREAK.id()) {
			token = new ClangBreak(par);
		}
		else if (node == ELEM_FUNCNAME.id()) {
			token = new ClangFuncNameToken(par, null);
		}
		else if (node == ELEM_TYPE.id()) {
			token = new ClangTypeToken(par);
		}
		else if (node == ELEM_COMMENT.id()) {
			token = new ClangCommentToken(par);
		}
		else if (node == ELEM_LABEL.id()) {
			token = new ClangLabelToken(par);
		}
		else if (node == ELEM_FIELD.id()) {
			token = new ClangFieldToken(par);
		}
		else {
			throw new DecoderException("Expecting token element");
		}
		token.decode(decoder, pfactory);
		return token;
	}

	static public ClangToken buildSpacer(ClangNode par, int indent, String indentStr) {
		String spacing = new String();
		for (int i = 0; i < indent; ++i) {
			spacing += indentStr;
		}
		return new ClangSyntaxToken(par, spacing);
	}

	@Override
	public String toString() {
		return text;
	}

	/**
	 * Get the high-level variable associate with this
	 * token or null otherwise
	 * @return HighVariable
	 */
	public HighVariable getHighVariable() {
		if (Parent() instanceof ClangVariableDecl) {
			return ((ClangVariableDecl) Parent()).getHighVariable();
		}
		return null;
	}

	/**
	 * Many tokens directly represent a variable in the data-flow
	 * @return the variable (Varnode) associated with this token or null
	 */
	public Varnode getVarnode() {
		return null;
	}

	/**
	 * Many tokens directly represent a pcode operator in the data-flow
	 * @return the operation (PcodeOp) associated with this token or null
	 */
	public PcodeOp getPcodeOp() {
		return null;
	}
}
