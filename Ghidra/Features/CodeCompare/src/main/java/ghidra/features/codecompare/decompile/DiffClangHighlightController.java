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
package ghidra.features.codecompare.decompile;

import java.awt.Color;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.*;
import ghidra.features.codecompare.graphanalysis.TokenBin;

/**
 * Class to handle Function Difference highlights for a decompiled function.
 */

public class DiffClangHighlightController extends LocationClangHighlightController
		implements DiffClangHighlightListener {

	private Set<ClangToken> diffTokenSet = new HashSet<>();
	private ClangToken locationToken;
	private TokenBin locationTokenBin;
	private List<TokenBin> allTokenBins;
	private DecompilerCodeComparisonOptions comparisonOptions;
	private DiffClangHighlightListener listener = new DummyListener();

	private DiffTokenHighlighter diffColorHighlighter;
	private BasicTokenHighlighter currentTokenHighlighter;

	// highlights the token in this highlighter for the selected token in the other highlighter
	private BasicTokenHighlighter matchingTokenHighlighter;

	public DiffClangHighlightController(DecompilerCodeComparisonOptions comparisonOptions) {
		this.comparisonOptions = comparisonOptions;
	}

	public void setDiffHighlights(List<TokenBin> highlightBins, Set<ClangToken> tokenSet) {
		this.allTokenBins = highlightBins;

		clearDiffHighlights();

		if (!tokenSet.isEmpty()) {
			Color color = comparisonOptions.getDiffHighlightColor();
			diffColorHighlighter = new DiffTokenHighlighter(new ArrayList<>(tokenSet), color);
			diffColorHighlighter.applyHighlights();
		}
		notifyListeners();
	}

	@Override
	public void fieldLocationChanged(FieldLocation location, Field field,
			EventTrigger trigger) {

		if (!(field instanceof ClangTextField textField)) {
			return;
		}

		// Get the token for the location so we can highlight its token bin. Also we will use it 
		// when notifying the other panel to highlight.
		ClangToken tok = textField.getToken(location);
		if (Objects.equals(locationToken, tok)) {
			return; // current location's token hasn't changed
		}

		clearPrimaryHighlights();
		clearCurrentLocationHighlight();
		clearMatchingTokenBin();

		highlightTokensBetweenParens(tok);
		highlightCurrentLocationToken(tok);

		listener.locationTokenChanged(locationTokenBin);
	}

	private void highlightTokensBetweenParens(ClangToken tok) {

		if (!(tok instanceof ClangSyntaxToken syntaxToken)) {
			return;
		}

		addPrimaryHighlightToTokensForParenthesis(syntaxToken, defaultParenColor);
		addPrimaryHighlightToTokensForBrace(syntaxToken, defaultParenColor);
	}

	private void highlightCurrentLocationToken(ClangToken tok) {

		TokenBin tokenBin = null;
		if (tok != null && allTokenBins != null) {
			tokenBin = TokenBin.getBinContainingToken(allTokenBins, tok);
		}

		Color binHlColor = comparisonOptions.getFocusedTokenIneligibleHighlightColor();
		if (tokenBin != null) {
			if (tokenBin.getMatch() != null) {
				binHlColor = comparisonOptions.getFocusedTokenMatchHighlightColor();
			}
			else {
				binHlColor = comparisonOptions.getFocusedTokenUnmatchedHighlightColor();
			}
		}

		locationToken = tok;
		locationTokenBin = tokenBin;

		List<ClangToken> tokens = List.of();
		if (tokenBin != null) {
			tokens = toList(tokenBin);
		}
		else if (tok != null) {
			tokens = List.of(tok);
		}

		installCurrentTokenHighlighter(tokens, binHlColor);
		refreshDiffHighlightsForCurrentLocationChange();
	}

	/*
	 * The diff highlighter is smart enough to ignore the token at the current location.  We have to
	 * kick it when the location changes so it will update the highlights.
	 */
	private void refreshDiffHighlightsForCurrentLocationChange() {
		if (diffColorHighlighter != null) {
			diffColorHighlighter.clearHighlights();
			diffColorHighlighter.applyHighlights();
		}
	}

	private static List<ClangToken> toList(TokenBin tokens) {
		return StreamSupport.stream(tokens.spliterator(), false).collect(Collectors.toList());
	}

	private void clearCurrentLocationHighlight() {

		if (currentTokenHighlighter != null) {
			currentTokenHighlighter.dispose();
			currentTokenHighlighter = null;
		}

		locationTokenBin = null;
		locationToken = null;
	}

	private void clearDiffHighlights() {

		if (diffColorHighlighter != null) {
			diffColorHighlighter.dispose();
			diffColorHighlighter = null;
		}

		diffTokenSet.clear();
	}

	private void clearMatchingTokenBin() {
		if (matchingTokenHighlighter != null) {
			matchingTokenHighlighter.dispose();
			matchingTokenHighlighter = null;
		}
	}

	private void installCurrentTokenHighlighter(List<ClangToken> tokens, Color highlightColor) {
		if (tokens.isEmpty()) {
			return;
		}

		currentTokenHighlighter = new BasicTokenHighlighter(tokens, highlightColor);
		currentTokenHighlighter.applyHighlights();
	}

	private void installMatchingTokenBinHighlighter(TokenBin tokenBin, Color highlightColor) {

		clearMatchingTokenBin();

		if (tokenBin == null) {
			return;
		}

		matchingTokenHighlighter = new BasicTokenHighlighter(tokenBin, highlightColor);
		matchingTokenHighlighter.applyHighlights();
	}

	public void setTokenChangedListener(DiffClangHighlightListener listener) {
		this.listener = listener == null ? new DummyListener() : listener;
	}

	@Override
	public void locationTokenChanged(TokenBin tokenBin) {
		clearCurrentLocationHighlight();
		refreshDiffHighlightsForCurrentLocationChange();

		// The token Changed in our other matching DiffClangHighlightController
		if (tokenBin != null) {
			TokenBin match = tokenBin.getMatch();
			Color color = comparisonOptions.getFocusedTokenMatchHighlightColor();
			installMatchingTokenBinHighlighter(match, color);
		}
	}

//=================================================================================================
// Inner Classes
//=================================================================================================

	/**
	 * Highlights a given set of tokens with the given color.
	 */
	private class BasicTokenHighlighter implements DecompilerHighlighter {

		private String id;
		protected List<ClangToken> tokens;
		private Color color;

		BasicTokenHighlighter(TokenBin tokens, Color color) {
			this(toList(tokens), color);
		}

		BasicTokenHighlighter(List<ClangToken> tokens, Color color) {
			this.color = color;
			UUID uuId = UUID.randomUUID();
			this.id = uuId.toString();
			this.tokens = tokens;
		}

		// subclass overrides this method
		protected List<ClangToken> getCurrentTokens() {
			return tokens;
		}

		@Override
		public void applyHighlights() {
			Supplier<? extends Collection<ClangToken>> tokenSupplier = this::getCurrentTokens;
			ColorProvider cp = t -> color;
			addHighlighterHighlights(this, tokenSupplier, cp);
		}

		@Override
		public void clearHighlights() {
			removeHighlighterHighlights(this);
		}

		@Override
		public void dispose() {
			removeHighlighterHighlights(this);
		}

		@Override
		public String getId() {
			return id;
		}
	}

	private class DiffTokenHighlighter extends BasicTokenHighlighter {

		DiffTokenHighlighter(List<ClangToken> tokens, Color color) {
			super(tokens, color);
		}

		@Override
		protected List<ClangToken> getCurrentTokens() {
			// ignore the selected token so that it paints with its own color and does not get 
			// blended with this highlighter's color
			return tokens.stream().filter(t -> t != locationToken).collect(Collectors.toList());
		}
	}

	private class DummyListener implements DiffClangHighlightListener {
		@Override
		public void locationTokenChanged(TokenBin tokenBin) {
			// stub
		}
	}
}
