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

import org.apache.commons.collections4.map.LazyMap;

import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompilerHighlighter;
import ghidra.program.model.listing.Function;

/**
 * A class to manage and track Decompiler highlights created by the user via the UI or from a 
 * script.  This class manages secondary and global highlights.  For a description of these terms, 
 * see {@link ClangHighlightController}.
 * <p>
 * These highlights will remain until cleared explicitly by the user or a client API call.  
 * Contrastingly, context highlights are cleared as the user moves the cursor around the Decompiler 
 * display.
 */
public class UserHighlights {

	private Map<Function, List<DecompilerHighlighter>> secondaryHighlightersByFunction =
		LazyMap.lazyMap(new HashMap<>(), f -> new ArrayList<>());

	// store the secondary highlighters here in addition to the map below so that we may discern
	// between secondary highlights and highlight service highlights
	private Set<DecompilerHighlighter> secondaryHighlighters = new HashSet<>();

	// all highlighters, including secondary and global highlight service highlighters
	private Map<DecompilerHighlighter, TokenHighlights> allHighlighterHighlights = new HashMap<>();

	// color supplier for secondary highlights
	private TokenHighlightColors secondaryHighlightColors = new TokenHighlightColors();

	Color getSecondaryColor(String text) {
		// Note: this call is used to generate colors for secondary highlighters that this API
		// creates.  Client highlighters will create their own colors.
		return secondaryHighlightColors.getColor(text);
	}

	String getAppliedColorsString() {
		return secondaryHighlightColors.getAppliedColorsString();
	}

	boolean hasSecondaryHighlights(Function function) {
		return !secondaryHighlightersByFunction.get(function).isEmpty();
	}

	Color getSecondaryHighlight(ClangToken token) {
		DecompilerHighlighter highlighter = getSecondaryHighlighter(token);
		if (highlighter != null) {
			TokenHighlights highlights = allHighlighterHighlights.get(highlighter);
			HighlightToken hlToken = highlights.get(token);
			return hlToken.getColor();
		}

		return null;
	}

	TokenHighlightColors getSecondaryHighlightColors() {
		return secondaryHighlightColors;
	}

	Set<DecompilerHighlighter> getSecondaryHighlighters(Function function) {
		return new HashSet<>(secondaryHighlightersByFunction.get(function));
	}

	Set<DecompilerHighlighter> getGlobalHighlighters() {
		Set<DecompilerHighlighter> allHighlighters = allHighlighterHighlights.keySet();
		Set<DecompilerHighlighter> results = new HashSet<>(allHighlighters);
		results.removeAll(secondaryHighlighters);
		return results;
	}

	List<DecompilerHighlighter> getSecondaryHighlightersByFunction(Function f) {
		return secondaryHighlightersByFunction.get(f);
	}

	TokenHighlights getHighlights(DecompilerHighlighter highlighter) {
		return allHighlighterHighlights.get(highlighter);
	}

	DecompilerHighlighter getSecondaryHighlighter(ClangToken token) {
		for (DecompilerHighlighter highlighter : secondaryHighlighters) {
			TokenHighlights highlights = allHighlighterHighlights.get(highlighter);
			HighlightToken hlToken = highlights.get(token);
			if (hlToken != null) {
				return highlighter;
			}
		}

		return null;
	}

	void addSecondaryHighlighter(Function function, DecompilerHighlighter highlighter) {

		// Note: this highlighter has likely already been added to this class, but has not
		//       yet been bound to the given function.
		secondaryHighlightersByFunction.get(function).add(highlighter);
		secondaryHighlighters.add(highlighter);
		allHighlighterHighlights.putIfAbsent(highlighter, new TokenHighlights());
	}

	// This adds the given highlighter.  This is for global and secondary highlights.  Secondary
	// highlights will be later registered to this class for the function they apply to.
	TokenHighlights add(DecompilerHighlighter highlighter) {
		allHighlighterHighlights.putIfAbsent(highlighter, new TokenHighlights());
		return allHighlighterHighlights.get(highlighter);
	}

	void remove(DecompilerHighlighter highlighter) {
		allHighlighterHighlights.remove(highlighter);
		secondaryHighlighters.remove(highlighter);

		Collection<List<DecompilerHighlighter>> lists = secondaryHighlightersByFunction.values();
		for (List<DecompilerHighlighter> highlighters : lists) {
			if (highlighters.remove(highlighter)) {
				break;
			}
		}
	}

	TokenHighlights get(DecompilerHighlighter highlighter) {
		return allHighlighterHighlights.get(highlighter);
	}

	void dispose() {
		secondaryHighlighters.clear();
		secondaryHighlightersByFunction.clear();
		allHighlighterHighlights.clear();
	}
}
