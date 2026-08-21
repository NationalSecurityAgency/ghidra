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
package ghidra.app.plugin.core.decompiler.taint;

import java.awt.Color;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.decompiler.CTokenHighlightMatcher;
import ghidra.app.decompiler.ClangToken;

/**
 * A highlighter maps highlight colors to ClangTokens in the decompilation. Which colors to use for each token is determined
 * by some strategy.
 * 
 * <p>
 * The VertexHighlighter applies a different color to each token. All of the highlighted tokens are tainted.
 * 
 * <p>
 * There are two determinations a Highlighter must make:
 * 
 * <ol><li>
 * Does the token match an element returned from a Source-Sink query that should be highlighted.
 * </li><li>
 * If a match is made, what color to apply to the token; the CONSISTENCY of a highlight color is determined by some
 *    characteristic of the returned query, e.g., a specific location, a specific variable name, a specific taint label.
 * </li></ol>   
 * Making BOTH of the above determinations require access to the query data.
 * 
 * <p>
 * The TaintProvider is a good place to determine whether there is a match; however, it should return the TaintLabelId instance
 * that captures critical information to make a color determination.
 */
public class VertexHighlighterMatcher implements CTokenHighlightMatcher {

	TaintCTokenHighlighterPalette palette;
	TaintProvider taintProvider;

	Map<String, Color> cachedHighlights;

	int nextColorIndex;

	public VertexHighlighterMatcher(TaintProvider taintProvider, TaintCTokenHighlighterPalette palette) {
		this.taintProvider = taintProvider;
		this.palette = palette;
		this.nextColorIndex = 0;
		this.cachedHighlights = new HashMap<>();
	}

	/**
	 * The basic method clients must implement to determine if a token should be
	 * highlighted. Returning a non-null Color will trigger the given token to be
	 * highlighted.
	 * 
	 * @param token the token
	 * @return the highlight color or null
	 */
	@Override
	public Color getTokenHighlight(ClangToken token) {

		return null;
	}

	public void clearCache() {
		cachedHighlights.clear();
	}

}
