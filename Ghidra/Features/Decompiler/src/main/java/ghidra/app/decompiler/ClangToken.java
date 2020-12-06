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

import java.awt.Color;
import java.util.List;

//import ghidra.app.plugin.core.decompile.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.*;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * Class representing a C code language token
 * May contain links back to pcode object
 */
public class ClangToken implements ClangNode {
	public final static int KEYWORD_COLOR = 0;
	public final static int TYPE_COLOR = 1;
	public final static int FUNCTION_COLOR = 2;
	public final static int COMMENT_COLOR = 3;
	public final static int VARIABLE_COLOR = 4;
	public final static int CONST_COLOR = 5;
	public final static int PARAMETER_COLOR = 6;
	public final static int GLOBAL_COLOR = 7;
	public final static int DEFAULT_COLOR = 8;

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
		syntax_type = getColor(null);
		lineparent = null;
	}

	public ClangToken(ClangNode par, String txt) {
		parent = par;
		text = txt;
		highlight = null;
		syntax_type = getColor(null);
	}

	public ClangToken(ClangNode par, String txt, String col) {
		parent = par;
		text = txt;
		highlight = null;
		syntax_type = getColor(col);
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

	public void restoreFromXML(XmlElement el, XmlElement end, PcodeFactory pfactory) {
		text = end.getText();
		String col = el.getAttribute(ClangXML.COLOR);
		syntax_type = getColor(col);
	}

	@Override
	public void flatten(List<ClangNode> list) {
		list.add(this);
	}

	static public ClangToken buildToken(ClangNode par, XmlPullParser parser,
			PcodeFactory pfactory) {
		XmlElement node =
			parser.start(ClangXML.VARIABLE, ClangXML.OP, ClangXML.SYNTAX, ClangXML.BREAK,
				ClangXML.FUNCNAME, ClangXML.TYPE, ClangXML.COMMENT, ClangXML.LABEL, ClangXML.FIELD);
		ClangToken token = null;
		if (node.getName().equals(ClangXML.VARIABLE)) {
			token = new ClangVariableToken(par);
		}
		else if (node.getName().equals(ClangXML.OP)) {
			token = new ClangOpToken(par);
		}
		else if (node.getName().equals(ClangXML.SYNTAX)) {
			token = new ClangSyntaxToken(par);
		}
		else if (node.getName().equals(ClangXML.BREAK)) {
			token = new ClangBreak(par);
		}
		else if (node.getName().equals(ClangXML.FUNCNAME)) {
			token = new ClangFuncNameToken(par, null);
		}
		else if (node.getName().equals(ClangXML.TYPE)) {
			token = new ClangTypeToken(par);
		}
		else if (node.getName().equals(ClangXML.COMMENT)) {
			token = new ClangCommentToken(par);
		}
		else if (node.getName().equals(ClangXML.LABEL)) {
			token = new ClangLabelToken(par);
		}
		else if (node.getName().equals(ClangXML.FIELD)) {
			token = new ClangFieldToken(par);
		}
		XmlElement end = parser.end(node);
		if (token != null) {
			token.restoreFromXML(node, end, pfactory);
		}
		return token;
	}

	public static int getColor(String col) {
		if (col != null) {
			if (col.equals(ClangXML.KEYWORD_COLOR)) {
				return KEYWORD_COLOR;
			}
			else if (col.equals(ClangXML.VARIABLE_COLOR)) {
				return VARIABLE_COLOR;
			}
			else if (col.equals(ClangXML.CONST_COLOR)) {
				return CONST_COLOR;
			}
			else if (col.equals(ClangXML.PARAMETER_COLOR)) {
				return PARAMETER_COLOR;
			}
			else if (col.equals(ClangXML.GLOBAL_COLOR)) {
				return GLOBAL_COLOR;
			}
			else if (col.equals(ClangXML.TYPE_COLOR)) {
				return TYPE_COLOR;
			}
			else if (col.equals(ClangXML.COMMENT_COLOR)) {
				return COMMENT_COLOR;
			}
			else if (col.equals(ClangXML.FUNCNAME_COLOR)) {
				return FUNCTION_COLOR;
			}
		}
		return DEFAULT_COLOR; // The default color
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
