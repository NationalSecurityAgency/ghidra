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

import java.awt.Color;
import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;

import org.apache.commons.collections4.IterableUtils;

import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompile.actions.TokenHighlightColorProvider;
import ghidra.program.model.pcode.PcodeOp;

/**
 * Class to handle highlights for a decompiled function
 */
public abstract class ClangHighlightController {

	public static ClangHighlightController dummyIfNull(ClangHighlightController c) {
		if (c == null) {
			return new NullClangHighlightController();
		}
		return c;
	}

	// Note: Most of the methods in this class were extracted from the ClangLayoutController class
	//       and the DecompilerPanel class.

	protected Color defaultHighlightColor = new Color(255, 255, 0, 128); // Default color for highlighting tokens
	protected Color defaultSpecialColor = new Color(255, 100, 0, 128); // Default color for specially highlighted tokens
	protected Color defaultParenColor = new Color(255, 255, 0, 128); // Default color for highlighting parentheses

	private Set<ClangToken> primaryHighlightTokens = new HashSet<>();
	private Set<ClangToken> secondaryHighlightTokens = new HashSet<>();
	private List<ClangHighlightListener> listeners = new ArrayList<>();

	public abstract void fieldLocationChanged(FieldLocation location, Field field,
			EventTrigger trigger);

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
	private ClangToken getHighlightedToken() {
		if (primaryHighlightTokens.size() == 1) {
			ClangToken[] tokenArray =
				primaryHighlightTokens.toArray(new ClangToken[primaryHighlightTokens.size()]);
			return tokenArray[0];
		}
		return null;
	}

	private void gatherAllTokens(ClangNode parentNode, Set<ClangToken> results) {

		int n = parentNode.numChildren();
		for (int i = 0; i < n; i++) {
			ClangNode node = parentNode.Child(i);
			if (node.numChildren() > 0) {
				gatherAllTokens(node, results);
			}
			else if (node instanceof ClangToken) {
				results.add((ClangToken) node);
			}
		}
	}

	public void clearPrimaryHighlights() {
		doClearHighlights(primaryHighlightTokens);
	}

	public void clearAllHighlights() {
		Iterable<ClangToken> allTokens =
			IterableUtils.chainedIterable(primaryHighlightTokens, secondaryHighlightTokens);
		for (ClangToken clangToken : allTokens) {
			clangToken.setHighlight(null);
			clangToken.setMatchingToken(false);
		}

		primaryHighlightTokens.clear();
		secondaryHighlightTokens.clear();
		notifyListeners();
	}

	private void doClearHighlights(Set<ClangToken> highlightTokens) {

		for (ClangToken clangToken : highlightTokens) {
			clangToken.setHighlight(null);
			clangToken.setMatchingToken(false);
		}

		highlightTokens.clear();
		notifyListeners();
	}

	public void addPrimaryHighlight() {
		// TODO 
	}

	public void addSecondaryHighlight() {
		// TODO 
	}

	public void addPrimaryHighlights(Supplier<? extends Collection<ClangToken>> tokens,
			Color hlColor) {
		Function<ClangToken, Color> colorProvider = token -> hlColor;
		addTokensToHighlights(tokens.get(), colorProvider, primaryHighlightTokens);
	}

	public void addPrimaryHighlights(ClangNode parentNode,
			TokenHighlightColorProvider colorProvider) {

		Set<ClangToken> tokens = new HashSet<>();
		gatherAllTokens(parentNode, tokens);
		addTokensToHighlights(tokens, colorProvider::getColor, tokens);
	}

	public void addPrimaryHighlights(ClangNode parentNode, Set<PcodeOp> ops, Color hlColor) {

		addPrimaryHighlights(parentNode, token -> {
			PcodeOp op = token.getPcodeOp();
			return ops.contains(op) ? hlColor : null;
		});
	}

	private void addPrimaryHighlights(Collection<ClangToken> tokens, Color hlColor) {
		Function<ClangToken, Color> colorProvider = token -> hlColor;
		addTokensToHighlights(tokens, colorProvider, primaryHighlightTokens);
	}

	private void addTokensToHighlights(Collection<ClangToken> tokens,
			Function<ClangToken, Color> colorProvider, Set<ClangToken> currentHighlights) {
		for (ClangToken clangToken : tokens) {
			Color color = colorProvider.apply(clangToken);
			doAddHighlight(clangToken, color, currentHighlights);
		}
		notifyListeners();
	}

	protected void addPrimaryHighlight(ClangToken token, Color highlightColor) {
		addPrimaryHighlights(Set.of(token), highlightColor);
	}

	private void doAddHighlight(ClangToken clangToken, Color highlightColor,
			Set<ClangToken> currentHighlights) {

		if (highlightColor == null) {
			return;
		}

		clangToken.setHighlight(highlightColor);
		currentHighlights.add(clangToken);
	}

	public void clearHighlight(ClangToken clangToken) {
		clangToken.setHighlight(null);
		primaryHighlightTokens.remove(clangToken);
		notifyListeners();
	}

	/**
	 * If input token is a parenthesis, highlight all
	 * tokens between it and its match
	 * @param tok potential parenthesis token
	 * @param highlightColor the highlight color
	 * @return a list of all tokens that were highlighted.
	 */
	protected List<ClangToken> addPrimaryHighlightToTokensForParenthesis(ClangSyntaxToken tok,
			Color highlightColor) {

		int paren = tok.getOpen();
		if (paren == -1) {
			paren = tok.getClose();
		}

		if (paren == -1) {
			return new ArrayList<>(); // Not a parenthesis
		}

		List<ClangToken> results = gatherContentsOfParenthesis(tok, paren);
		addPrimaryHighlights(results, highlightColor);
		return results;
	}

	private List<ClangToken> gatherContentsOfParenthesis(ClangSyntaxToken tok, int parenId) {

		List<ClangToken> results = new ArrayList<>();
		int parenCount = 0;
		ClangNode par = tok.Parent();
		while (par != null) {
			boolean outside = true;
			if (!(par instanceof ClangTokenGroup)) {
				par = par.Parent();
				continue;
			}

			List<ClangNode> list = new ArrayList<>();
			((ClangTokenGroup) par).flatten(list);

			for (ClangNode node : list) {
				ClangToken tk = (ClangToken) node;
				if (tk instanceof ClangSyntaxToken) {
					ClangSyntaxToken syn = (ClangSyntaxToken) tk;
					if (syn.getOpen() == parenId) {
						parenCount++;
						outside = false;
					}
					else if (syn.getClose() == parenId) {
						parenCount++;
						outside = true;
						results.add(syn);
					}
				}

				if (!outside) {
					results.add(tk);
				}

				if (parenCount == 2) {
					return results; // found both parens; break out early
				}
			}
			par = par.Parent();
		}

		return results;
	}

	public void addHighlightBrace(ClangSyntaxToken token, Color highlightColor) {

		if (DecompilerUtils.isBrace(token)) {
			highlightBrace(token, highlightColor);
			notifyListeners();
		}
	}

	private void highlightBrace(ClangSyntaxToken startToken, Color highlightColor) {

		ClangSyntaxToken matchingBrace = DecompilerUtils.getMatchingBrace(startToken);
		if (matchingBrace != null) {
			matchingBrace.setMatchingToken(true); // this is a signal to the painter
			addPrimaryHighlights(Set.of(matchingBrace), highlightColor);
		}
	}

	public void addListener(ClangHighlightListener listener) {
		listeners.add(listener);
	}

	public void removeListener(ClangHighlightListener listener) {
		listeners.remove(listener);
	}

	private void notifyListeners() {
		for (ClangHighlightListener listener : listeners) {
			listener.tokenHighlightsChanged();
		}
	}
}
