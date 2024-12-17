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

public class LabelHighlighterMatcher implements CTokenHighlightMatcher {

	TaintCTokenHighlighterPalette palette;
	TaintProvider taintProvider;

	// stores previously established colors for consistency.
	// the key should be some unique String that is WHAT you are using to
	// define consistent highlighting.
	Map<String, Color> cachedHighlights;

	final int nextColorIndex;

	public LabelHighlighterMatcher(TaintProvider taintProvider, TaintCTokenHighlighterPalette palette) {
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
