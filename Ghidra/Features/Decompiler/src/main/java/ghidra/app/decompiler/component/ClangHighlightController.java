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

import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompile.actions.TokenHighlightColorProvider;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.ColorUtils;
import util.CollectionUtils;

/**
 * Class to handle highlights for a decompiled function.
 * 
 * <p>This class does not painting directly.  Rather, this class tracks the currently highlighted
 * tokens and then sets the highlight color on the token when it is highlighted and clears the 
 * highlight color when the highlight is removed.
 */
public abstract class ClangHighlightController {

	public static Color DEFAULT_HIGHLIGHT_COLOR = new Color(255, 255, 0, 128);

	public static ClangHighlightController dummyIfNull(ClangHighlightController c) {
		if (c == null) {
			return new NullClangHighlightController();
		}
		return c;
	}

	// Note: Most of the methods in this class were extracted from the ClangLayoutController class
	//       and the DecompilerPanel class.

	protected Color defaultHighlightColor = DEFAULT_HIGHLIGHT_COLOR;
	protected Color defaultParenColor = DEFAULT_HIGHLIGHT_COLOR;

	private TokenHighlights primaryHighlightTokens = new TokenHighlights();
	private TokenHighlights secondaryHighlightTokens = new TokenHighlights();

	// TODO rename 'secondary highlight color manager'
	private TokenHighlightColors secondaryHighlightColors = new TokenHighlightColors();

	private List<ClangHighlightListener> listeners = new ArrayList<>();

	public abstract void fieldLocationChanged(FieldLocation location, Field field,
			EventTrigger trigger);

	void setHighlightColor(Color c) {
		defaultHighlightColor = c;
	}

	public String getHighlightedText() {
		ClangToken highlightedToken = getHighlightedToken();
		if (highlightedToken != null) {
			return highlightedToken.getText();
		}
		return null;
	}

	public TokenHighlights getSecondaryHighlightedTokens() {
		return secondaryHighlightTokens;
	}

	/**
	 * Return the current highlighted token (if exists and unique)
	 * @return token or null
	 */
	private ClangToken getHighlightedToken() {
		if (primaryHighlightTokens.size() == 1) {
			HighlightToken hlToken = CollectionUtils.any(primaryHighlightTokens);
			return hlToken.getToken();
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
		notifyListeners();
	}

	public void clearSecondaryHighlights() {
		doClearHighlights(secondaryHighlightTokens);
		notifyListeners();
	}

	public void clearAllHighlights() {
		doClearHighlights(primaryHighlightTokens);
		doClearHighlights(secondaryHighlightTokens);
		notifyListeners();
	}

	// TODO try to reconcile 'tokenhighlights' vs 'highlighttokens' ( and highlighttoken)
	private void doClearHighlights(TokenHighlights highlightTokens) {

		Iterator<HighlightToken> it = highlightTokens.iterator();
		while (it.hasNext()) {
			HighlightToken highlight = it.next();
			it.remove();
			ClangToken token = highlight.getToken();
			token.setMatchingToken(false);
			updateHighlightColor(token);
		}
		highlightTokens.clear();
	}

	public void toggleSecondaryHighlight(ClangToken token,
			Supplier<? extends Collection<ClangToken>> lazyTokens) {

		String text = token.getText();

		// toggle the highlight		
		HighlightToken highlight = secondaryHighlightTokens.get(token);
		if (highlight == null) {
			Color highlightColor = secondaryHighlightColors.getColor(text);
			addSecondaryHighlights(lazyTokens, highlightColor);
		}
		else {
			removeSecondaryHighlights(lazyTokens);
		}
	}

	public boolean hasSecondaryHighlight(ClangToken token) {
		return secondaryHighlightTokens.contains(token);
	}

	public void removeSecondaryHighlights(ghidra.program.model.listing.Function function) {
		Set<HighlightToken> oldHighlights =
			secondaryHighlightTokens.removeTokensByFunction(function);
		for (HighlightToken hl : oldHighlights) {
			ClangToken token = hl.getToken();
			updateHighlightColor(token);
		}
		notifyListeners();
	}

	public HighlightToken removeSecondaryHighlight(ClangToken token) {
		HighlightToken hlToken = secondaryHighlightTokens.get(token);
		secondaryHighlightTokens.remove(token);
		return hlToken;
	}

	private void removeSecondaryHighlights(Supplier<? extends Collection<ClangToken>> tokens) {
		for (ClangToken clangToken : tokens.get()) {
			secondaryHighlightTokens.remove(clangToken);
			updateHighlightColor(clangToken);
		}
		notifyListeners();
	}

	public void addSecondaryHighlights(Supplier<? extends Collection<ClangToken>> tokens,
			Color hlColor) {
		Function<ClangToken, Color> colorProvider = token -> hlColor;
		addTokensToHighlights(tokens.get(), colorProvider, secondaryHighlightTokens);
	}

	@Deprecated // for use by subclasses 
	protected void addHighlight(ClangToken tok, Color hlColor) {
		addPrimaryHighlight(tok, hlColor);
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
		addTokensToHighlights(tokens, colorProvider::getColor, primaryHighlightTokens);
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
			Function<ClangToken, Color> colorProvider, TokenHighlights currentHighlights) {
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
			TokenHighlights currentHighlights) {

		if (highlightColor == null) {
			return;
		}

		// store the actual requested color
		currentHighlights.add(new HighlightToken(clangToken, highlightColor));
		updateHighlightColor(clangToken);
	}

	private void updateHighlightColor(ClangToken t) {
		// set the color to the current combined value of both highlight types
		Color combinedColor = getCombinedColor(t);
		t.setHighlight(combinedColor);
	}

	public Color getCombinedColor(ClangToken t) {

		HighlightToken primaryHl = primaryHighlightTokens.get(t);
		HighlightToken secondaryHl = secondaryHighlightTokens.get(t);
		Color primary = primaryHl == null ? null : primaryHl.getColor();
		Color secondary = secondaryHl == null ? null : secondaryHl.getColor();

		if (primary == null) {
			if (secondary == null) {
				return null;
			}
			return secondary;
		}

		if (secondary == null) {
			return primary;
		}

		return ColorUtils.blend(primary, secondary, .8f);
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
