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

import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;

// TODO revisit having the panel's live here... we need this if clients interact with this 
// object directly.  If they go through the panel, then we do not need them here
public class TokenHighlights {

	private int minColorSaturation = 100;
	private int defaultColorAlpha = 100;

	// TODO private HighlightColorSource

	private DecompilerPanel panel;
	// TODO private Map<TokenKey, HighlightToken> highlightsByToken = new HashMap<>();

	private Map<TokenKey, HighlightToken> nullMap = Collections.unmodifiableMap(new HashMap<>());
	private Map<Function, Map<TokenKey, HighlightToken>> highlightsByFunction =
		LazyMap.lazyMap(new HashMap<>(), f -> f == null ? nullMap : new HashMap<>());

	public TokenHighlights(DecompilerPanel panel) {
		this.panel = panel;
	}

	public TokenHighlights copyHighlights(DecompilerPanel otherPanel, Function function) {

		TokenHighlights newHighlights = new TokenHighlights(otherPanel);

		Map<TokenKey, HighlightToken> highlightsByToken = highlightsByFunction.get(function);
		Map<TokenKey, HighlightToken> newHighlightsByToken = new HashMap<>(highlightsByToken);
		newHighlights.highlightsByFunction.put(function, newHighlightsByToken);
		return newHighlights;
	}

	private Map<TokenKey, HighlightToken> getHighlightsByToken(HighlightToken t) {
		return highlightsByFunction.get(getFunction(t.getToken()));
	}

	private Map<TokenKey, HighlightToken> getHighlightsByToken(ClangToken t) {
		return highlightsByFunction.get(getFunction(t));
	}

	private Function getFunction(ClangToken t) {

		// TODO verify that we can always get a function

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

	public void add(HighlightToken t) {
		Function f = t.getFunction();
		Map<TokenKey, HighlightToken> highlightsByToken = highlightsByFunction.get(f);
		highlightsByToken.put(new TokenKey(t), t);
		notifyListeners();
	}

	public HighlightToken get(ClangToken t) {
		Map<TokenKey, HighlightToken> highlightsByToken = getHighlightsByToken(t);
		TokenKey key = new TokenKey(t);
		return highlightsByToken.get(key);
	}

	public Collection<HighlightToken> get(Function f) {
		return highlightsByFunction.get(f).values();
	}

	public void clear() {
		highlightsByFunction.clear();
		notifyListeners();
	}

	public boolean contains(HighlightToken t) {
		TokenKey key = new TokenKey(t);
		Map<TokenKey, HighlightToken> highlightsByToken = getHighlightsByToken(t);
		return highlightsByToken.containsKey(key);
	}

	public void remove(HighlightToken t) {
		TokenKey key = new TokenKey(t);
		Map<TokenKey, HighlightToken> highlightsByToken = getHighlightsByToken(t);
		highlightsByToken.remove(key);
		notifyListeners();
	}

	public void remove(Function function) {
		highlightsByFunction.remove(function);
		notifyListeners();
	}

	// TODO remove this
	public void notifyListeners() {

		//
		// TODO to remove this, the clients that change this class would have to forcibly rebuild the highlights
		//  -it seems simpler to have one place manager notifications
		//  -OTOH, it seems wasteful to completely rebuild all secondary highlights when adding
		//         or removing a single one
		// 

		panel.rebuildSecondaryHighlightTokens();
	}

	@Override
	public String toString() {
		return highlightsByFunction.values().toString();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class TokenKey {
		private ClangToken token;

		TokenKey(ClangToken token) {
			this.token = Objects.requireNonNull(token);
		}

		public TokenKey(HighlightToken t) {
			this(t.getToken());
		}

		@Override
		public int hashCode() {
			String text = token.getText();
			return text == null ? 0 : text.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}

			if (getClass() != obj.getClass()) {
				return false;
			}

			ClangToken otherToken = ((TokenKey) obj).token;
			if (token.getClass() != otherToken.getClass()) {
				return false;
			}

			if (!Objects.equals(token.getText(), otherToken.getText())) {
				return false;
			}

			ClangLine lineParent = token.getLineParent();
			ClangLine otherLineParent = otherToken.getLineParent();
			if (!sameLines(lineParent, otherLineParent)) {
				return false;
			}
			if (lineParent == null) {
				return false;
			}

			int positionInLine = lineParent.indexOfToken(token);
			int otherPositionInLine = otherLineParent.indexOfToken(otherToken);
			return positionInLine == otherPositionInLine;
		}

		private boolean sameLines(ClangLine l1, ClangLine l2) {

			if (l1 == null) {
				if (l2 != null) {
					return false;
				}
				return true;
			}
			else if (l2 == null) {
				return false;
			}

			return l1.getLineNumber() == l2.getLineNumber();
		}

		@Override
		public String toString() {
			return token.toString();
		}
	}

	// TODO move up; clean up

	private Map<String, Color> colorsByName =
		LazyMap.lazyMap(new HashMap<>(), s -> generateColor());

	private Color generateColor() {
		return new Color((int) (minColorSaturation + Math.random() * (256 - minColorSaturation)),
			(int) (minColorSaturation + Math.random() * (256 - minColorSaturation)),
			(int) (minColorSaturation + Math.random() * (256 - minColorSaturation)),
			defaultColorAlpha);
	}

	public Color getColor(String text) {
		return colorsByName.get(text);
	}
}
