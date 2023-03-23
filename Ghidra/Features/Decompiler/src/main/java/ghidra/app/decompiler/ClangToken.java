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

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.awt.Color;
import java.util.List;

//import ghidra.app.plugin.core.decompile.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.*;

/**
 * Class representing a source code language token.
 * A token has numerous display attributes and may link to the data-flow analysis
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

	/**
	 * Get the element representing an entire line of text that contains this element
	 * @return the containing ClangLine
	 */
	public ClangLine getLineParent() {
		return lineparent;
	}

	/**
	 * Set (change) the line which this text element part of.  
	 * @param line is the new ClangLine
	 */
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

	/**
	 * Get the background highlight color used to render this token, or null if not highlighted
	 * @return the Color or null
	 */
	public Color getHighlight() {
		return highlight;
	}

	/**
	 * Set whether or not additional "matching" highlighting is applied to this token.
	 * Currently this means a bounding box is drawn around the token.
	 * @param matchingToken is true to enable highlighting, false to disable
	 */
	public void setMatchingToken(boolean matchingToken) {
		this.matchingToken = matchingToken;
	}

	/**
	 * @return true if this token should be displayed with "matching" highlighting
	 */
	public boolean isMatchingToken() {
		return matchingToken;
	}

	/**
	 * @return true if this token represents a variable (in source code)
	 */
	public boolean isVariableRef() {
		return false;
	}

	/**
	 * Get the "syntax" type (color) associated with this token (keyword, type, etc)
	 * @return the color code
	 */
	public int getSyntaxType() {
		return syntax_type;
	}

	/**
	 * Set the "syntax" type (color) associated with this token
	 * @param syntax_type is the color code to set
	 */
	void setSyntaxType(int syntax_type) {
		this.syntax_type = syntax_type;
	}

	/**
	 * @return this token's display text as a string
	 */
	public String getText() {
		return text;
	}

	/**
	 * Set this token's display text.
	 * @param text is the string to set
	 */
	void setText(String text) {
		this.text = text;
	}

	/**
	 * Decode this token from the current position in an encoded stream
	 * @param decoder is the decoder for the stream
	 * @param pfactory is used to look up p-code objects associated with the token
	 * @throws DecoderException for problems decoding the stream
	 */
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

	/**
	 * Decode one specialized token from the current position in an encoded stream.  This
	 * serves as a factory for allocating the various objects derived from ClangToken
	 * @param node is the particular token type (already) decoded from the stream
	 * @param par is the text grouping which will contain the token
	 * @param decoder is the decoder for the stream
	 * @param pfactory is used to look up p-code objects associated with tokens
	 * @return the new ClangToken
	 * @throws DecoderException for problems decoding the stream
	 */
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

	/**
	 * Add a spacer token to the given text grouping
	 * @param par is the text grouping
	 * @param indent is the number of levels to indent
	 * @param indentStr is a string representing containg the number of spaces in one indent level
	 * @return the new spacer token
	 */
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
		return null;
	}

	/**
	 * Get the symbol associated with this token or null otherwise.
	 * This token may be directly associated with the symbol or a reference, in which
	 * case the symbol is looked up in the containing HighFunction
	 * @param highFunction is the function
	 * @return HighSymbol
	 */
	public HighSymbol getHighSymbol(HighFunction highFunction) {
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
