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
package ghidra.app.decompiler.component;

import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.awt.Color;
import java.util.*;

import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;

/**
 * Class to handle highlights for a decompiled function.
 */

public class ClangHighlightController {

	// Note: Most of the methods in this class were extracted from the ClangLayoutController class
	//       and the DecompilerPanel class.

	protected Color defaultNonFunctionBackgroundColor = new Color(220, 220, 220);
	protected Color defaultHighlightColor = new Color(255, 255, 0, 128); // Default color for highlighting tokens
	protected Color defaultSpecialColor = new Color(255, 100, 0, 128); // Default color for specially highlighted tokens
	protected Color defaultParenColor = new Color(255, 255, 0, 128); // Default color for highlighting parentheses

	protected HashSet<ClangToken> highlightTokenSet = new HashSet<ClangToken>();

	protected ArrayList<ClangHighlightListener> highlightListenerList =
		new ArrayList<ClangHighlightListener>();

	public ClangHighlightController() {
	}

	void loadOptions(DecompileOptions options) {
		Color currentVariableHighlightColor = options.getCurrentVariableHighlightColor();
		if (currentVariableHighlightColor != null) {
			setDefaultHighlightColor(currentVariableHighlightColor);
		}
	}

	public void setDefaultHighlightColor(Color highlightColor) {
		defaultHighlightColor = highlightColor;
		notifyListeners();
	}

	public void setDefaultSpecialColor(Color specialColor) {
		defaultSpecialColor = specialColor;
		notifyListeners();
	}

	public void setDefaultParenColor(Color parenColor) {
		defaultParenColor = parenColor;
		notifyListeners();
	}

	public Color getDefaultHighlightColor() {
		return defaultHighlightColor;
	}

	public Color getDefaultSpecialColor() {
		return defaultSpecialColor;
	}

	public Color getDefaultParenColor() {
		return defaultParenColor;
	}

	public String getHighlightedText() {
		ClangToken highlightedToken = getHighlightedToken();
		if (highlightedToken != null) {
			return highlightedToken.getText();
		}
		return null;
	}

	/**
	 * Return the current highlighted token (if exists and unique)
	 * @return token or null
	 */
	public ClangToken getHighlightedToken() {
		if (highlightTokenSet.size() == 1) {
			ClangToken[] tokenArray =
				highlightTokenSet.toArray(new ClangToken[highlightTokenSet.size()]);
			return tokenArray[0];
		}
		return null;
	}

	public void addVarnodesToHighlight(ClangNode parentNode, Set<Varnode> varnodes,
			Color highlightColor, Varnode specificvn, PcodeOp specificop, Color specialColor) {
		int nchild = parentNode.numChildren();
		for (int i = 0; i < nchild; ++i) {
			ClangNode node = parentNode.Child(i);
			if (node.numChildren() > 0) {
				addVarnodesToHighlight(node, varnodes, highlightColor, specificvn, specificop,
					specialColor);
			}
			else if (node instanceof ClangToken) {
				ClangToken tok = (ClangToken) node;
				Varnode vn = DecompilerUtils.getVarnodeRef(tok);
				if (varnodes.contains(vn))
					addHighlight(tok, highlightColor);
				if (vn == specificvn) { // Look for specific varnode to label with specialColor
					if ((specificop != null) && (tok.getPcodeOp() == specificop))
						addHighlight(tok, specialColor);
				}
			}
		}
		notifyListeners();
	}

	public void addPcodeOpsToHighlight(ClangNode parentNode, Set<PcodeOp> ops, Color highlightColor) {
		int nchild = parentNode.numChildren();
		for (int i = 0; i < nchild; ++i) {
			ClangNode node = parentNode.Child(i);
			if (node.numChildren() > 0) {
				addPcodeOpsToHighlight(node, ops, highlightColor);
			}
			else if (node instanceof ClangToken) {
				ClangToken tok = (ClangToken) node;
				PcodeOp op = tok.getPcodeOp();
				if (ops.contains(op))
					addHighlight(tok, highlightColor);
			}
		}
		notifyListeners();
	}

	public void addTokensToHighlights(List<ClangToken> tokenList, Color highlightColor) {
		for (ClangToken clangToken : tokenList) {
			doAddHighlight(clangToken, highlightColor);
		}
		notifyListeners();
	}

	public void clearHighlights() {
		for (ClangToken clangToken : highlightTokenSet) {
			clangToken.setHighlight(null);
			if (clangToken.isMatchingToken()) {
				clangToken.setMatchingToken(false);
			}
		}
		highlightTokenSet.clear();
		notifyListeners();
	}

	public void addHighlight(ClangToken clangToken, Color highlightColor) {
		doAddHighlight(clangToken, highlightColor);
		notifyListeners();
	}

	public void doAddHighlight(ClangToken clangToken, Color highlightColor) {
		clangToken.setHighlight(highlightColor);
		highlightTokenSet.add(clangToken);
	}

	public void clearHighlight(ClangToken clangToken) {
		clangToken.setHighlight(null);
		highlightTokenSet.remove(clangToken);
		notifyListeners();
	}

	public boolean isHighlighted(ClangToken clangToken) {
		return highlightTokenSet.contains(clangToken);
	}

	/**
	 * If input token is a parenthesis, highlight all
	 * tokens between it and its match
	 * @param tok = potential parenthesis token
	 * @return a list of all tokens that were highlighted.
	 */
	public List<ClangToken> addHighlightParen(ClangSyntaxToken tok, Color highlightColor) {
		ArrayList<ClangToken> tokenList = new ArrayList<ClangToken>();
		int paren = tok.getOpen();
		if (paren == -1)
			paren = tok.getClose();
		if (paren == -1)
			return tokenList; // Not a parenthesis
		ClangNode par = tok.Parent();
		while (par != null) {
			boolean outside = true;
			if (par instanceof ClangTokenGroup) {
				ArrayList<ClangNode> list = new ArrayList<ClangNode>();
				((ClangTokenGroup) par).flatten(list);
				for (int i = 0; i < list.size(); ++i) {
					ClangToken tk = (ClangToken) list.get(i);
					if (tk instanceof ClangSyntaxToken) {
						ClangSyntaxToken syn = (ClangSyntaxToken) tk;
						if (syn.getOpen() == paren)
							outside = false;
						else if (syn.getClose() == paren) {
							outside = true;
							addHighlight(syn, highlightColor);
							tokenList.add(syn);
						}
					}
					if (!outside) {
						addHighlight(tk, highlightColor);
						tokenList.add(tk);
					}
				}
			}
			par = par.Parent();
		}
		return tokenList;
	}

	public void addHighlightBrace(ClangSyntaxToken token, Color highlightColor) {
		ClangNode parent = token.Parent();
		String text = token.getText();
		if ("{".equals(text)) {
			highlightBrace(token, parent, false, highlightColor);
			return;
		}

		if ("}".equals(text)) {
			highlightBrace(token, parent, true, highlightColor);
			return;
		}
		notifyListeners();
	}

	private void highlightBrace(ClangSyntaxToken startToken, ClangNode parent, boolean forward,
			Color highlightColor) {
		List<ClangNode> list = new ArrayList<ClangNode>();
		parent.flatten(list);

		if (!forward) {
			Collections.reverse(list);
		}

		Stack<ClangSyntaxToken> braceStack = new Stack<ClangSyntaxToken>();
		for (int i = 0; i < list.size(); ++i) {
			ClangToken token = (ClangToken) list.get(i);
			if (token instanceof ClangSyntaxToken) {
				ClangSyntaxToken syntaxToken = (ClangSyntaxToken) token;

				if (startToken == syntaxToken) {
					// found our starting token, take the current value on the stack
					ClangSyntaxToken matchingBrace = braceStack.pop();
					matchingBrace.setMatchingToken(true);
					addHighlight(matchingBrace, highlightColor);
					return;
				}

				if (!isBrace(syntaxToken)) {
					continue;
				}

				if (braceStack.isEmpty()) {
					braceStack.push(syntaxToken);
					continue;
				}

				ClangSyntaxToken lastToken = braceStack.peek();
				if (isMatchingBrace(lastToken, syntaxToken)) {
					braceStack.pop();
				}
				else {
					braceStack.push(syntaxToken);
				}
			}
		}
	}

	private boolean isBrace(ClangSyntaxToken token) {
		String text = token.getText();
		return "{".equals(text) || "}".equals(text);
	}

	private boolean isMatchingBrace(ClangSyntaxToken braceToken, ClangSyntaxToken otherBraceToken) {
		String brace = braceToken.getText();
		String otherBrace = otherBraceToken.getText();
		return !brace.equals(otherBrace);
	}

	/**
	 * Add highlighting to tokens that are surrounded by
	 * highlighted tokens, but which have no address
	 */
	public void addHighlightFill() {
		ClangTokenGroup lastgroup = null;
		ArrayList<ClangNode> newhi = new ArrayList<ClangNode>();
		ArrayList<Color> newcolor = new ArrayList<Color>();
		for (ClangToken tok : highlightTokenSet) {
			if (tok.Parent() instanceof ClangTokenGroup) {
				ClangTokenGroup par = (ClangTokenGroup) tok.Parent();
				if (par == lastgroup)
					continue;
				lastgroup = par;
				int beg = -1;
				int end = par.numChildren();
				for (int j = 0; j < par.numChildren(); ++j) {
					if (par.Child(j) instanceof ClangToken) {
						ClangToken token = (ClangToken) par.Child(j);
						Color curcolor = token.getHighlight();
						if (curcolor != null) {
							if (beg == -1)
								beg = j;
							else {
								end = j;
								for (int k = beg + 1; k < end; ++k) {
									if (par.Child(k) instanceof ClangToken) {
										newhi.add(par.Child(k));
										newcolor.add(curcolor);
									}
								}
								beg = j;
							}
						}
						else if (token.getMinAddress() != null) {
							beg = -1;
						}
					}
					else
						beg = -1;
				}
			}
		}
		for (int i = 0; i < newhi.size(); ++i) {
			ClangToken tok = (ClangToken) newhi.get(i);
			if (tok.getHighlight() != null)
				continue;
			addHighlight(tok, newcolor.get(i));
		}
		notifyListeners();
	}

	public void fieldLocationChanged(FieldLocation location, Field field, EventTrigger trigger) {

		// Do nothing.

//		clearHighlights();
//
//		if (!(field instanceof ClangTextField)) {
//			return;
//		}
//
//		ClangToken tok = ((ClangTextField) field).getToken(location);
//		if (tok == null) {
//			return;
//		}
//
////		// clear any highlighted searchResults
////		decompilerPanel.setSearchResults(null);
//
//		addHighlight(tok, defaultHighlightColor);
//		if (tok instanceof ClangSyntaxToken) {
//			addHighlightParen((ClangSyntaxToken) tok, defaultParenColor);
//			addHighlightBrace((ClangSyntaxToken) tok, defaultParenColor);
//		}
	}

	public boolean addListener(ClangHighlightListener listener) {
		return highlightListenerList.add(listener);
	}

	public boolean removeListener(ClangHighlightListener listener) {
		return highlightListenerList.remove(listener);
	}

	private void notifyListeners() {
		for (ClangHighlightListener listener : highlightListenerList) {
			listener.tokenHighlightsChanged();
		}
	}
}
