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
package ghidra.codecompare;

import java.awt.Color;
import java.util.*;
import java.util.stream.Collectors;

import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import generic.theme.GColor;
import ghidra.app.decompiler.ClangSyntaxToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.*;
import ghidra.codecompare.graphanalysis.TokenBin;
import ghidra.util.ColorUtils;
import ghidra.util.SystemUtilities;
import util.CollectionUtils;

/**
 * Class to handle Function Difference highlights for a decompiled function.
 */

public class DiffClangHighlightController extends LocationClangHighlightController
		implements DiffClangHighlightListener {

	private Set<ClangToken> diffTokenSet = new HashSet<>();
	private ClangToken locationToken;
	private TokenBin locationTokenBin;
	private List<TokenBin> highlightBins;
	private List<DiffClangHighlightListener> listenerList = new ArrayList<>();
	private TokenBin matchingTokenBin;
	private DecompilerCodeComparisonOptions comparisonOptions;

	public DiffClangHighlightController(DecompilerCodeComparisonOptions comparisonOptions) {
		this.comparisonOptions = comparisonOptions;
	}

	public void clearDiffHighlights() {
		doClearDiffHighlights();
		notifyListeners();
	}

	private void doClearDiffHighlights() {
		ClangToken[] array = diffTokenSet.toArray(new ClangToken[diffTokenSet.size()]);
		for (ClangToken clangToken : array) {
			clearDiffHighlight(clangToken);
		}
	}

	private void clearDiffHighlight(ClangToken clangToken) {
		Color highlight = clangToken.getHighlight();
		if (highlight != null && highlight.equals(comparisonOptions.getDiffHighlightColor())) {
			clangToken.setHighlight(null);
		}
		diffTokenSet.remove(clangToken);
	}

	private void clearNonDiffHighlight(ClangToken clangToken) {
		if (diffTokenSet.contains(clangToken)) {
			clangToken.setHighlight(comparisonOptions.getDiffHighlightColor());
		}
		else {
			clangToken.setHighlight(null);
		}
		if (clangToken.isMatchingToken()) {
			clangToken.setMatchingToken(false);
		}
	}

	public void setDiffHighlights(List<TokenBin> highlightBins, Set<ClangToken> tokenSet) {
		this.highlightBins = highlightBins;
		doClearDiffHighlights();
		for (ClangToken clangToken : tokenSet) {
			clangToken.setHighlight(comparisonOptions.getDiffHighlightColor());
			diffTokenSet.add(clangToken);
		}
		notifyListeners();
	}

	@Override
	public void fieldLocationChanged(FieldLocation location, Field field, EventTrigger trigger) {

		if (!(field instanceof ClangTextField)) {
			return;
		}

		// Get the token for the location so we can highlight its token bin.
		// Also we will use it when notifying the other panel to highlight.
		ClangToken tok = ((ClangTextField) field).getToken(location);
		if (SystemUtilities.isEqual(locationToken, tok)) {
			return; // Current location's token hasn't changed.
		}

		// Undo any highlight of the previous matching tokenBin.
		if (matchingTokenBin != null && matchingTokenBin.getMatch() != null) {
			clearTokenBinHighlight(matchingTokenBin.getMatch());
			matchingTokenBin = null;
		}

		clearCurrentLocationHighlight();

		clearPrimaryHighlights();
		addPrimaryHighlight(tok, defaultHighlightColor);
		if (tok instanceof ClangSyntaxToken) {
			List<ClangToken> tokens = addPrimaryHighlightToTokensForParenthesis(
				(ClangSyntaxToken) tok, defaultParenColor);
			reHighlightDiffs(tokens);
			addBraceHighlight((ClangSyntaxToken) tok, defaultParenColor);
		}

		TokenBin tokenBin = null;
		if (tok != null) {
			Color highlightColor = comparisonOptions.getFocusedTokenIneligibleHighlightColor(); // Don't know
			if (highlightBins != null) {
				tokenBin = TokenBin.getBinContainingToken(highlightBins, tok);
				if (tokenBin != null) {
					if (tokenBin.getMatch() != null) {
						highlightColor = comparisonOptions.getFocusedTokenMatchHighlightColor();
					}
					else if (tokenBin.getMatch() == null) {
						highlightColor = comparisonOptions.getFocusedTokenUnmatchedHighlightColor();
					}
					else {
						// All the tokens that didn't fall into the "has a match" or "no match"
						// categories above are in a single token bin.
						// We don't want all these highlighted at the same time, so set the
						// tokenBin to null. By doing this, only the current token gets highlighted.
						tokenBin = null;
					}
				}
			}
			locationToken = tok;
			locationTokenBin = tokenBin;
			if (tokenBin == null) {
				addPrimaryHighlight(tok, highlightColor);
			}
			else {
				addTokenBinHighlight(tokenBin, highlightColor);
			}
		}

		// Notify other decompiler panel highlight controller we have a new location token.
		for (DiffClangHighlightListener listener : listenerList) {
			listener.locationTokenChanged(tok, tokenBin);
		}
	}

	private void reHighlightDiffs(List<ClangToken> tokenList) {
		Color averageColor =
			ColorUtils.blend(defaultParenColor, comparisonOptions.getDiffHighlightColor(), 0.5);
		for (ClangToken clangToken : tokenList) {
			if (diffTokenSet.contains(clangToken)) {
				clangToken.setHighlight(averageColor);
			}
		}
	}

	private void clearCurrentLocationHighlight() {
		if (locationTokenBin != null) {
			clearTokenBinHighlight(locationTokenBin);
			locationTokenBin = null;
			locationToken = null;
		}
		if (locationToken != null) {
			clearNonDiffHighlight(locationToken);
			locationToken = null;
		}
	}

	private void addTokenBinHighlight(TokenBin tokenBin, Color highlightColor) {
		for (ClangToken token : tokenBin) {
			addPrimaryHighlight(token, highlightColor);
		}
	}

	private void clearTokenBinHighlight(TokenBin tokenBin) {
		for (ClangToken token : tokenBin) {
			clearNonDiffHighlight(token);
		}
	}

	private void doClearHighlights(TokenHighlights tokens) {
		List<ClangToken> clangTokens =
			CollectionUtils.asStream(tokens).map(ht -> ht.getToken()).collect(Collectors.toList());
		for (ClangToken clangToken : clangTokens) {
			clearNonDiffHighlight(clangToken);
		}
		tokens.clear();
		notifyListeners();
	}

	@Override
	public void clearPrimaryHighlights() {
		doClearHighlights(getPrimaryHighlights());
	}

	public boolean addListener(DiffClangHighlightListener listener) {
		return listenerList.add(listener);
	}

	public boolean removeListener(DiffClangHighlightListener listener) {
		return listenerList.remove(listener);
	}

	@Override
	public void locationTokenChanged(ClangToken tok, TokenBin tokenBin) {
		clearCurrentLocationHighlight();

		// The token Changed in our other matching DiffClangHighlightController
		highlightMatchingToken(tok, tokenBin);
	}

	private void highlightMatchingToken(ClangToken tok, TokenBin tokenBin) {
		// Undo any highlight of the previous matching tokenBin.
		if (matchingTokenBin != null && matchingTokenBin.getMatch() != null) {
			clearTokenBinHighlight(matchingTokenBin.getMatch());
		}

		// Highlight the new matching tokenBin.
		if (tokenBin != null && tokenBin.getMatch() != null) {
			addTokenBinHighlight(tokenBin.getMatch(),
				comparisonOptions.getFocusedTokenMatchHighlightColor());
		}

		matchingTokenBin = tokenBin;
	}
}
