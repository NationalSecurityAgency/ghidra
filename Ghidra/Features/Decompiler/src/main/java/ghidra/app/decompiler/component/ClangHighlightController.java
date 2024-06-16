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
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.apache.commons.collections4.map.LazyMap;

import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import generic.theme.GColor;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.ColorUtils;
import util.CollectionUtils;

/**
 * Class to handle highlights for a decompiled function.
 * 
 * <p>This class does not paint directly.  Rather, this class tracks the currently highlighted
 * tokens and then sets the highlight color on the token when it is highlighted and clears the
 * highlight color when the highlight is removed.
 * 
 * <p>This class maintains the following types of highlights:
 * <UL>
 * 	<LI>Primary Highlights - triggered by user clicking and some user actions; considered transient
 *  	and get cleared whenever the location changes.  These highlights show state such as the
 * 		current field, impact of a variable (via a slicing action), or related syntax (such as
 * 		matching braces)
 *  </LI>
 *  <LI>Secondary Highlights - triggered by the user to show all occurrences of a particular
 *  	variable; they will stay until they are manually cleared by a user action.  The user can
 *  	apply multiple secondary highlights at the same time, with different colors for each
 *  	highlight.
 *   	<B>These highlights apply to the function in use when the highlight is created.  Thus,
 *  	each function has a unique set of highlights that is maintained between decompilation.</B>
 *  </LI>
 *  <LI>Global Highlights - triggered by clients of the {@link DecompilerHighlightService}; they
 *  	will stay until the client of the service clears the highlight.
 *  	<B>These highlights apply to every function that is decompiler.</B>
 *  </LI>
 * </UL>
 * 
 * <p>When multiple highlights overlap, their colors will be blended.
 */
public abstract class ClangHighlightController {

	public static Color DEFAULT_HIGHLIGHT_COLOR =
		new GColor("color.bg.decompiler.highlights.default");

	public static ClangHighlightController dummyIfNull(ClangHighlightController c) {
		if (c == null) {
			return new NullClangHighlightController();
		}
		return c;
	}

	protected Color defaultHighlightColor = DEFAULT_HIGHLIGHT_COLOR;
	protected Color defaultParenColor = DEFAULT_HIGHLIGHT_COLOR;

	private TokenHighlights primaryHighlightTokens = new TokenHighlights();

	private Map<Function, List<ClangDecompilerHighlighter>> secondaryHighlightersbyFunction =
		LazyMap.lazyMap(new HashMap<>(), f -> new ArrayList<>());

	// store the secondary highlighters here in addition to the map below so that we may discern
	// between secondary highlights and highlight service highlights
	private Set<ClangDecompilerHighlighter> secondaryHighlighters = new HashSet<>();

	// all highlighters, including secondary and highlight service highlighters
	private Map<ClangDecompilerHighlighter, TokenHighlights> highlighterHighlights =
		new HashMap<>();

	// color supplier for secondary highlights
	private TokenHighlightColors secondaryHighlightColors = new TokenHighlightColors();

	/**
	 * A counter to track updates so that clients know when a buffered highlight request is invalid
	 */
	private long updateId;

	private List<ClangHighlightListener> listeners = new ArrayList<>();

	public abstract void fieldLocationChanged(FieldLocation location, Field field,
			EventTrigger trigger);

	void setHighlightColor(Color c) {
		defaultHighlightColor = c;
	}

	/**
	 * Returns the color provider used by this class to generate colors.  The initial color
	 * selection is random.  Repeated calls to get a color for the same token will return the same
	 * color.
	 * @return the color provider
	 */
	public ColorProvider getRandomColorProvider() {
		return token -> secondaryHighlightColors.getColor(token.getText());
	}

	/**
	 * Returns the token that has the primary highlight applied, if any.  If multiple tokens are
	 * highlighted, then the return value is arbitrary.
	 * @return the highlighted text
	 */
	public String getPrimaryHighlightedText() {
		ClangToken highlightedToken = getHighlightedToken();
		if (highlightedToken != null) {
			return highlightedToken.getText();
		}
		return null;
	}

	/**
	 * An value that is updated every time a new highlight is added.  This allows clients to
	 * determine if a buffered update request is still valid.
	 * @return the value
	 */
	public long getUpdateId() {
		return updateId;
	}

	public boolean hasPrimaryHighlight(ClangToken token) {
		return primaryHighlightTokens.contains(token);
	}

	public boolean hasSecondaryHighlight(ClangToken token) {
		return getSecondaryHighlight(token) != null;
	}

	public boolean hasSecondaryHighlights(Function function) {
		return !secondaryHighlightersbyFunction.get(function).isEmpty();
	}

	public Color getSecondaryHighlight(ClangToken token) {
		DecompilerHighlighter highlighter = getSecondaryHighlighter(token);
		if (highlighter != null) {
			TokenHighlights highlights = highlighterHighlights.get(highlighter);
			HighlightToken hlToken = highlights.get(token);
			return hlToken.getColor();
		}

		return null;
	}

	public TokenHighlightColors getSecondaryHighlightColors() {
		return secondaryHighlightColors;
	}

	public TokenHighlights getPrimaryHighlights() {
		return primaryHighlightTokens;
	}

	/**
	 * Returns all secondary highlighters for the given function.   This allows clients to update
	 * the secondary highlight state of a given function without affecting highlights applied to
	 * other functions.
	 * @param function the function
	 * @return the highlighters
	 */
	public Set<ClangDecompilerHighlighter> getSecondaryHighlighters(Function function) {
		return new HashSet<>(secondaryHighlightersbyFunction.get(function));
	}

	/**
	 * Returns all global highlighters installed in this controller.  The global highlighters apply
	 * to all functions.  This is in contrast to secondary highlighters, which are
	 * function-specific.
	 * @return the highlighters
	 */
	public Set<ClangDecompilerHighlighter> getGlobalHighlighters() {
		Set<ClangDecompilerHighlighter> allHighlighters = highlighterHighlights.keySet();
		Set<ClangDecompilerHighlighter> results = new HashSet<>(allHighlighters);
		results.removeAll(secondaryHighlighters);
		return results;
	}

	/**
	 * Gets all highlights for the given highlighter.
	 * @param highlighter the highlighter
	 * @return the highlights
	 * @see #getPrimaryHighlights()
	 */
	public TokenHighlights getHighlighterHighlights(DecompilerHighlighter highlighter) {
		return highlighterHighlights.get(highlighter);
	}

	/**
	 * Return the current highlighted token (if exists and unique)
	 * @return token or null
	 */
	public ClangToken getHighlightedToken() {
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
		Consumer<ClangToken> clearAll = token -> {
			token.setMatchingToken(false);
			updateHighlightColor(token);
		};

		doClearHighlights(primaryHighlightTokens, clearAll);
		notifyListeners();
	}

	private void doClearHighlights(TokenHighlights tokenHighlights, Consumer<ClangToken> clearer) {
		Iterator<HighlightToken> it = tokenHighlights.iterator();
		while (it.hasNext()) {
			HighlightToken highlight = it.next();

			// must remove the highlight before calling the clearer as that may call back into the
			// TokenHighlights we are clearing
			it.remove();
			ClangToken token = highlight.getToken();
			clearer.accept(token);
		}
	}

	/**
	 * Toggles the primary highlight state of the given set of tokens.  If the given tokens do not
	 * all have the same highlight state (highlights on or off), then the highlights will be
	 * cleared.  If all tokens are not highlighted, then they will all become highlighted.
	 * 
	 * @param hlColor the highlight color
	 * @param tokens the tokens
	 */
	public void togglePrimaryHighlights(Color hlColor, Supplier<List<ClangToken>> tokens) {

		boolean isAllHighlighted = true;
		for (ClangToken otherToken : tokens.get()) {
			if (!hasPrimaryHighlight(otherToken)) {
				isAllHighlighted = false;
				break;
			}
		}

		// this is a bit odd, but whenever we change the primary highlights, we always reset any
		// previous primary highlight (see javadoc header)
		clearPrimaryHighlights();

		if (isAllHighlighted) {
			// nothing to do; we toggled from 'all on' to 'all off'
			return;
		}

		addPrimaryHighlights(tokens, hlColor);
	}

	/**
	 * Removes all secondary highlights for the given function
	 * @param f the function
	 */
	public void removeSecondaryHighlights(Function f) {

		List<ClangDecompilerHighlighter> highlighters = secondaryHighlightersbyFunction.get(f);
		for (ClangDecompilerHighlighter highlighter : highlighters) {
			TokenHighlights highlights = highlighterHighlights.get(highlighter);
			Consumer<ClangToken> clearHighlight = token -> updateHighlightColor(token);
			doClearHighlights(highlights, clearHighlight);
		}
		highlighters.clear();
		notifyListeners();
	}

	/**
	 * Removes all secondary highlights for the given token
	 * @param token the token
	 * @see #removeSecondaryHighlights(Function)
	 */
	public void removeSecondaryHighlights(ClangToken token) {
		DecompilerHighlighter highlighter = getSecondaryHighlighter(token);
		if (highlighter != null) {
			highlighter.dispose(); // this will call removeHighlighterHighlights()
		}
		notifyListeners();
	}

	private DecompilerHighlighter getSecondaryHighlighter(ClangToken token) {
		for (DecompilerHighlighter highlighter : secondaryHighlighters) {
			TokenHighlights highlights = highlighterHighlights.get(highlighter);
			HighlightToken hlToken = highlights.get(token);
			if (hlToken != null) {
				return highlighter;
			}
		}

		return null;
	}

	public void removeHighlighter(DecompilerHighlighter highlighter) {

		removeHighlighterHighlights(highlighter);
		highlighterHighlights.remove(highlighter);
		secondaryHighlighters.remove(highlighter);

		Collection<List<ClangDecompilerHighlighter>> lists =
			secondaryHighlightersbyFunction.values();
		for (List<ClangDecompilerHighlighter> highlighters : lists) {
			if (highlighters.remove(highlighter)) {
				break;
			}
		}
	}

	/**
	 * Removes all highlights for this highlighter across all functions
	 * @param highlighter the highlighter
	 */
	public void removeHighlighterHighlights(DecompilerHighlighter highlighter) {

		TokenHighlights highlighterTokens = highlighterHighlights.get(highlighter);
		if (highlighterTokens == null) {
			return;
		}

		Consumer<ClangToken> clearHighlight = token -> updateHighlightColor(token);
		doClearHighlights(highlighterTokens, clearHighlight);
		notifyListeners();
	}

	/**
	 * Adds the given secondary highlighter, but does not create any highlights.  All secondary
	 * highlighters pertain to a given function.
	 * @param function the function
	 * @param highlighter the highlighter
	 */
	public void addSecondaryHighlighter(Function function, ClangDecompilerHighlighter highlighter) {

		// Note: this highlighter has likely already been added the the this class, but has not
		//       yet been bound to the given function.
		secondaryHighlightersbyFunction.get(function).add(highlighter);
		secondaryHighlighters.add(highlighter);
		highlighterHighlights.putIfAbsent(highlighter, new TokenHighlights());
	}

	// Note: this is used for all highlight types, secondary and highlighter service highlighters
	public void addHighlighter(ClangDecompilerHighlighter highlighter) {
		highlighterHighlights.putIfAbsent(highlighter, new TokenHighlights());
	}

	// Note: this is used for all highlight types, secondary and highlighter service highlights
	public void addHighlighterHighlights(ClangDecompilerHighlighter highlighter,
			Supplier<? extends Collection<ClangToken>> tokens,
			ColorProvider colorProvider) {

		Objects.requireNonNull(highlighter);
		TokenHighlights highlighterTokens =
			highlighterHighlights.computeIfAbsent(highlighter, k -> new TokenHighlights());
		addTokensToHighlights(tokens.get(), colorProvider, highlighterTokens);
	}

	private void addPrimaryHighlights(Supplier<? extends Collection<ClangToken>> tokens,
			Color hlColor) {
		ColorProvider colorProvider = token -> hlColor;
		addTokensToHighlights(tokens.get(), colorProvider, primaryHighlightTokens);
	}

	public void addPrimaryHighlights(ClangNode parentNode, Set<PcodeOp> ops, Color hlColor) {

		addPrimaryHighlights(parentNode, token -> {
			PcodeOp op = token.getPcodeOp();
			return ops.contains(op) ? hlColor : null;
		});
	}

	public void addPrimaryHighlights(ClangNode parentNode, ColorProvider colorProvider) {

		Set<ClangToken> tokens = new HashSet<>();
		gatherAllTokens(parentNode, tokens);
		addTokensToHighlights(tokens, colorProvider::getColor, primaryHighlightTokens);
	}

	private void addPrimaryHighlights(Collection<ClangToken> tokens, Color hlColor) {
		ColorProvider colorProvider = token -> hlColor;
		addTokensToHighlights(tokens, colorProvider, primaryHighlightTokens);
	}

	private void addTokensToHighlights(Collection<ClangToken> tokens,
			ColorProvider colorProvider, TokenHighlights currentHighlights) {

		updateId++;

		for (ClangToken clangToken : tokens) {
			Color color = colorProvider.getColor(clangToken);
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

	private void add(List<Color> colors, HighlightToken hlToken) {
		if (hlToken != null) {
			colors.add(hlToken.getColor());
		}
	}

	private void add(List<Color> colors, Color c) {
		if (c != null) {
			colors.add(c);
		}
	}

	/**
	 * Returns the current highlight color for the given token, based upon all known highlights,
	 * primary, secondary and highlighters
	 * @param t the token
	 * @return the color
	 */
	public Color getCombinedColor(ClangToken t) {

		// note: not sure whether we should always blend all colors or decide to allow some
		//       highlighters have precedence for highlighting

		HighlightToken primaryHl = primaryHighlightTokens.get(t);
		Color blendedHlColor = blendHighlighterColors(t);

		List<Color> allColors = new ArrayList<>();
		add(allColors, primaryHl);
		add(allColors, blendedHlColor);

		Color blended = blend(allColors);
		return blended;
	}

	public Color blend(List<Color> colors) {

		if (colors.isEmpty()) {
			return null;
		}

		if (colors.size() == 1) {
			return CollectionUtils.any(colors);
		}

		Color lastColor = colors.get(0);
		for (int i = 1; i < colors.size(); i++) {
			Color nextColor = colors.get(i);
			lastColor = ColorUtils.blend(lastColor, nextColor, .8f);
		}

		return lastColor;
	}

	private Color blendHighlighterColors(ClangToken token) {

		Function function = getFunction(token);
		if (function == null) {
			return null; // not sure if this can happen
		}

		Set<ClangDecompilerHighlighter> global = getGlobalHighlighters();
		Set<ClangDecompilerHighlighter> secondary = getSecondaryHighlighters(function);
		Iterable<ClangDecompilerHighlighter> it = CollectionUtils.asIterable(global, secondary);
		Color lastColor = null;
		for (ClangDecompilerHighlighter highlighter : it) {
			TokenHighlights highlights = highlighterHighlights.get(highlighter);
			HighlightToken hlToken = highlights.get(token);
			if (hlToken == null) {
				continue;
			}

			Color nextColor = hlToken.getColor();
			if (lastColor != null) {
				lastColor = ColorUtils.blend(lastColor, nextColor, .8f);
			}
			else {
				lastColor = nextColor;
			}
		}

		return lastColor;
	}

	private Function getFunction(ClangToken t) {
		ClangFunction cFunction = t.getClangFunction();
		if (cFunction == null) {
			return null;
		}

		HighFunction highFunction = cFunction.getHighFunction();
		if (highFunction == null) {
			return null;
		}
		return highFunction.getFunction();
	}

	/**
	 * If input token is a parenthesis, highlight all tokens between it and its match
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

	public void addBraceHighlight(ClangSyntaxToken token, Color highlightColor) {

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

	protected void notifyListeners() {
		for (ClangHighlightListener listener : listeners) {
			listener.tokenHighlightsChanged();
		}
	}

	public void dispose() {
		listeners.clear();
		primaryHighlightTokens.clear();
		secondaryHighlighters.clear();
		secondaryHighlightersbyFunction.clear();
		highlighterHighlights.clear();
	}
}
