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
 * 	<LI>Context Highlights - triggered by user clicking and some user actions; considered transient
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
 *  <LI>Service Highlights - triggered by clients of the {@link DecompilerHighlightService}; they
 *  	will be stored in this class until the client of the service clears the highlight.  These
 *      can be global (applied to all functions) or specific to a given function.  Each user 
 *      highlight will be called to generate highlights when a function is first decompiled.
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

	private TokenHighlights contextHighlightTokens = new TokenHighlights();
	private UserHighlights userHighlights = new UserHighlights();

	/**
	 * A counter to track updates so that clients know when a buffered highlight request is invalid
	 */
	private long updateId;

	// arbitrary value chosen by guessing; this can be changed if needed
	private int maxColorBlendSize = 5;
	private boolean isRebuilding;

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
	public ColorProvider getGeneratedColorProvider() {
		return new GeneratedColorProvider();
	}

	/**
	 * An value that is updated every time a new highlight is added.  This allows clients to
	 * determine if a buffered update request is still valid.
	 * @return the value
	 */
	public long getUpdateId() {
		return updateId;
	}

	public boolean hasContextHighlight(ClangToken token) {
		return contextHighlightTokens.contains(token);
	}

	public boolean hasSecondaryHighlight(ClangToken token) {
		return getSecondaryHighlight(token) != null;
	}

	public boolean hasSecondaryHighlights(Function function) {
		return userHighlights.hasSecondaryHighlights(function);
	}

	public Color getSecondaryHighlight(ClangToken token) {
		return userHighlights.getSecondaryHighlight(token);
	}

	public TokenHighlightColors getSecondaryHighlightColors() {
		return userHighlights.getSecondaryHighlightColors();
	}

	public TokenHighlights getPrimaryHighlights() {
		return contextHighlightTokens;
	}

	/**
	 * Returns all secondary highlighters for the given function.   This allows clients to update
	 * the secondary highlight state of a given function without affecting highlights applied to
	 * other functions.
	 * @param function the function
	 * @return the highlighters
	 */
	public Set<DecompilerHighlighter> getSecondaryHighlighters(Function function) {
		return userHighlights.getSecondaryHighlighters(function);
	}

	/**
	 * Returns all highlight service highlighters installed in this controller.  The global
	 * highlighters apply to all functions.  This is in contrast to secondary highlighters, which 
	 * are function-specific.
	 * @return the highlighters
	 */
	public Set<DecompilerHighlighter> getServiceHighlighters() {
		return userHighlights.getServiceHighlighters();
	}

	public void reapplyAllHighlights(Function function) {
		//
		// Under normal operation, we rebuild colors as highlighters are added and removed.  Doing
		// this for one highlighter is fast.  Doing it for a large number of highlighters can be 
		// slow.  When rebuilding all highlights, disable color calculation until the rebuild is
		// finished.  This allows all highlights to calculate their matches without the color 
		// blending affecting performance.
		//
		isRebuilding = true;
		Set<DecompilerHighlighter> service = getServiceHighlighters();
		Set<DecompilerHighlighter> secondary = getSecondaryHighlighters(function);
		Iterable<DecompilerHighlighter> it = CollectionUtils.asIterable(service, secondary);

		try {
			for (DecompilerHighlighter highlighter : it) {
				highlighter.clearHighlights();
				highlighter.applyHighlights();
			}
		}
		finally {
			isRebuilding = false;
		}

		// gather all highlighted tokens and then update their color
		Set<ClangToken> allTokens = new HashSet<>();
		it = CollectionUtils.asIterable(service, secondary);
		for (DecompilerHighlighter highlighter : it) {
			TokenHighlights hlTokens = userHighlights.add(highlighter);
			for (HighlightToken hlToken : hlTokens) {
				allTokens.add(hlToken.getToken());
			}
		}

		for (ClangToken token : allTokens) {
			updateHighlightColor(token);
		}
	}

	/**
	 * Gets all highlights for the given highlighter.
	 * @param highlighter the highlighter
	 * @return the highlights
	 * @see #getPrimaryHighlights()
	 */
	public TokenHighlights getHighlighterHighlights(DecompilerHighlighter highlighter) {
		return userHighlights.getHighlights(highlighter);
	}

	/**
	 * Return the current highlighted token (if exists and unique)
	 * @return token or null
	 */
	public ClangToken getHighlightedToken() {
		if (contextHighlightTokens.size() == 1) {
			HighlightToken hlToken = CollectionUtils.any(contextHighlightTokens);
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

		doClearHighlights(contextHighlightTokens, clearAll);
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
		for (ClangToken token : tokens.get()) {
			if (!hasContextHighlight(token)) {
				isAllHighlighted = false;
				break;
			}
		}

		// this is a bit odd, but whenever we change the primary highlights, we always reset any
		// previous primary highlight (see javadoc header)
		clearPrimaryHighlights();

		if (isAllHighlighted) {
			return; // nothing to do; we toggled from 'all on' to 'all off'
		}

		addPrimaryHighlights(tokens, hlColor);
	}

	/**
	 * Removes all secondary highlights for the given function
	 * @param f the function
	 */
	public void removeSecondaryHighlights(Function f) {

		List<DecompilerHighlighter> highlighters =
			userHighlights.getSecondaryHighlightersByFunction(f);

		for (DecompilerHighlighter highlighter : highlighters) {
			TokenHighlights highlights = userHighlights.getHighlights(highlighter);
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
		DecompilerHighlighter highlighter = userHighlights.getSecondaryHighlighter(token);
		if (highlighter != null) {
			highlighter.dispose(); // this will call removeHighlighterHighlights()
		}
		notifyListeners();
	}

	public void removeHighlighter(DecompilerHighlighter highlighter) {
		removeHighlighterHighlights(highlighter);
		userHighlights.remove(highlighter);
	}

	/**
	 * Removes all highlights for this highlighter across all functions
	 * @param highlighter the highlighter
	 */
	public void removeHighlighterHighlights(DecompilerHighlighter highlighter) {

		TokenHighlights highlighterTokens = userHighlights.get(highlighter);
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
	public void addSecondaryHighlighter(Function function, DecompilerHighlighter highlighter) {
		userHighlights.addSecondaryHighlighter(function, highlighter);
	}

	// Note: this is used for all highlight types, secondary and highlighter service highlighters
	public void addHighlighter(ClangDecompilerHighlighter highlighter) {
		userHighlights.add(highlighter);
	}

	// Note: this is used for all highlight types, secondary and highlighter service highlights
	public void addHighlighterHighlights(DecompilerHighlighter highlighter,
			Supplier<? extends Collection<ClangToken>> tokens, ColorProvider colorProvider) {

		Objects.requireNonNull(highlighter);
		TokenHighlights highlighterTokens = userHighlights.add(highlighter);
		addTokensToHighlights(tokens.get(), colorProvider, highlighterTokens);
	}

	private void addPrimaryHighlights(Supplier<? extends Collection<ClangToken>> tokens,
			Color hlColor) {
		addPrimaryHighlights(tokens.get(), hlColor);
	}

	private void addPrimaryHighlights(Collection<ClangToken> tokens, Color hlColor) {
		ColorProvider colorProvider = new DefaultColorProvider("Tokens Highlight Color", hlColor);
		addTokensToHighlights(tokens, colorProvider, contextHighlightTokens);
	}

	public void addPrimaryHighlights(ClangNode parentNode, Set<PcodeOp> ops, Color hlColor) {

		ColorProvider colorProvider = new DefaultColorProvider("PcodeOp Highlight Color", hlColor) {
			@Override
			public Color getColor(ClangToken token) {
				PcodeOp op = token.getPcodeOp();
				return ops.contains(op) ? hlColor : null;
			}
		};

		addPrimaryHighlights(parentNode, colorProvider);
	}

	public void addPrimaryHighlights(ClangNode parentNode, ColorProvider colorProvider) {

		Set<ClangToken> tokens = new HashSet<>();
		gatherAllTokens(parentNode, tokens);
		addTokensToHighlights(tokens, colorProvider, contextHighlightTokens);
	}

	private void addTokensToHighlights(Collection<ClangToken> tokens, ColorProvider colorProvider,
			TokenHighlights currentHighlights) {

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

		if (isRebuilding) {
			return;
		}

		// set the color to the current combined value of all highlight types
		Color combinedColor = getCombinedColor(t);
		t.setHighlight(combinedColor);
	}

	private void add(Set<Color> colors, HighlightToken hlToken) {
		if (hlToken != null) {
			colors.add(hlToken.getColor());
		}
	}

	private void add(Set<Color> colors, Color c) {
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

		HighlightToken primaryHl = contextHighlightTokens.get(t);
		Color blendedHlColor = blendHighlighterColors(t);

		Set<Color> allColors = new HashSet<>();
		add(allColors, primaryHl);
		add(allColors, blendedHlColor);

		return blend(allColors);
	}

	public Color blend(Set<Color> colors) {

		if (colors.isEmpty()) {
			return null;
		}

		Iterator<Color> it = colors.iterator();
		Color lastColor = it.next();
		while (it.hasNext()) {
			Color nextColor = it.next();
			lastColor = ColorUtils.blend(lastColor, nextColor, .8f);
		}
		return lastColor;
	}

	private Color blendHighlighterColors(ClangToken token) {

		Function function = getFunction(token);
		if (function == null) {
			return null; // not sure if this can happen
		}

		Set<DecompilerHighlighter> service = getServiceHighlighters();
		Set<DecompilerHighlighter> secondary = getSecondaryHighlighters(function);
		Iterable<DecompilerHighlighter> it = CollectionUtils.asIterable(service, secondary);
		Set<Color> colors = new HashSet<>();
		for (DecompilerHighlighter highlighter : it) {
			TokenHighlights highlights = userHighlights.get(highlighter);
			HighlightToken hlToken = highlights.get(token);
			if (hlToken == null) {
				continue;
			}

			Color nextColor = hlToken.getColor();
			colors.add(nextColor);
			if (colors.size() == maxColorBlendSize) {
				break;
			}
		}

		return blend(colors);
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

	protected void addPrimaryHighlightToTokensForBrace(ClangSyntaxToken token,
			Color highlightColor) {

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
		contextHighlightTokens.clear();
		userHighlights.dispose();
	}

	private class GeneratedColorProvider implements ColorProvider {

		@Override
		public Color getColor(ClangToken token) {
			return userHighlights.getSecondaryColor(token.getText());
		}

		@Override
		public String toString() {
			return "Generated Color Provider " + userHighlights.getAppliedColorsString();
		}
	}

}
