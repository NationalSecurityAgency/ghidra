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
import java.util.Map.Entry;

import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;

/**
 * A simple class to manage {@link HighlightToken}s used to create highlights in the Decompiler.
 * This class allows clients to access highlights either by a {@link ClangToken} or a 
 * {@link HighlightToken}.
 */
public class TokenHighlights implements Iterable<HighlightToken> {

	private Map<TokenKey, HighlightToken> highlightsByToken = new HashMap<>();

	public Map<String, Color> copyHighlightsByName() {
		Map<String, Color> results = new HashMap<>();

		Collection<HighlightToken> values = highlightsByToken.values();
		for (HighlightToken hl : values) {
			String name = hl.getToken().getText();
			results.put(name, hl.getColor());
		}

		return results;
	}

	private TokenKey getKey(HighlightToken ht) {
		return new TokenKey(ht);
	}

	private TokenKey getKey(ClangToken t) {
		return new TokenKey(t);
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
	 * Returns true if there are not highlights
	 * @return true if there are not highlights
	 */
	public boolean isEmpty() {
		return size() == 0;
	}

	/**
	 * Returns the number of highlights
	 * @return the number of highlights
	 */
	public int size() {
		return highlightsByToken.size();
	}

	/**
	 * Adds the given highlight to this container
	 * @param t the highlight
	 */
	public void add(HighlightToken t) {
		highlightsByToken.put(getKey(t), t);
	}

	/**
	 * Gets the current highlight for the given token
	 * @param t the token
	 * @return the highlight
	 */
	public HighlightToken get(ClangToken t) {
		return highlightsByToken.get(getKey(t));
	}

	/**
	 * Returns all highlights for the given function
	 * 
	 * @param f the function
	 * @return the highlights
	 */
	public Set<HighlightToken> getHighlightsByFunction(Function f) {
		Set<HighlightToken> results = new HashSet<>();
		Set<TokenKey> keys = getHighlightKeys(f);
		for (TokenKey key : keys) {
			HighlightToken hl = highlightsByToken.get(key);
			results.add(hl);
		}

		return results;
	}

	/**
	 * Returns true if this class has a highlight for the given token
	 * @param t the token
	 * @return true if this class has a highlight for the given token
	 */
	public boolean contains(ClangToken t) {
		return highlightsByToken.containsKey(getKey(t));
	}

	/**
	 * Removes all highlights from this container
	 */
	public void clear() {
		highlightsByToken.clear();
	}

	/**
	 * Removes the highlight for the given token
	 * @param t the token
	 */
	public void remove(ClangToken t) {
		highlightsByToken.remove(getKey(t));
	}

	/**
	 * Removes all highlights associated with the given function
	 * 
	 * @param function the function
	 * @return the removed highlights; empty if no highlights existed
	 */
	public Set<HighlightToken> removeHighlightsByFunction(Function function) {
		Set<HighlightToken> oldHighlights = new HashSet<>();
		Set<TokenKey> keys = getHighlightKeys(function);
		for (TokenKey key : keys) {
			HighlightToken hl = highlightsByToken.remove(key);
			oldHighlights.add(hl);
		}

		return oldHighlights;
	}

	private Set<TokenKey> getHighlightKeys(Function function) {
		Set<TokenKey> results = new HashSet<>();

		Set<Entry<TokenKey, HighlightToken>> entries = highlightsByToken.entrySet();
		for (Entry<TokenKey, HighlightToken> entry : entries) {
			HighlightToken highlight = entry.getValue();
			ClangToken token = highlight.getToken();
			Function tokenFunction = getFunction(token);
			if (function.equals(tokenFunction)) {
				results.add(entry.getKey());
			}
		}

		return results;
	}

	@Override
	public Iterator<HighlightToken> iterator() {
		return highlightsByToken.values().iterator();
	}

	@Override
	public String toString() {
		return highlightsByToken.values().toString();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	// a key that allows us to equate tokens that are not the same instance
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
}
