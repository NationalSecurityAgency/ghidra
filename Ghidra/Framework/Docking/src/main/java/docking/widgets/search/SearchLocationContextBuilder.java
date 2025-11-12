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
package docking.widgets.search;

import java.util.ArrayList;
import java.util.List;

import docking.widgets.search.SearchLocationContext.*;
import generic.json.Json;

/**
 * A builder for {@link SearchLocationContext} objects.  Use {@link #append(String)} for normal
 * text pieces.  Use {@link #appendMatch(String)} for text that is meant to be rendered specially
 * by the context class.
 */
public class SearchLocationContextBuilder {

	private List<Part> parts = new ArrayList<>();

	/**
	 * Appends the given text to this builder.
	 * @param text the text
	 * @return this builder
	 */
	public SearchLocationContextBuilder append(String text) {
		if (text == null) {
			text = "";
		}
		parts.add(new BasicPart(text));
		return this;
	}

	/**
	 * Appends the given text to this builder.   This text represents a client-defined 'match' that
	 * will be rendered with markup when {@link SearchLocationContext#getBoldMatchingText()} is
	 * called.
	 * @param text the text
	 * @return this builder
	 */
	public SearchLocationContextBuilder appendMatch(String text) {
		if (text == null) {
			throw new NullPointerException("Match text cannot be null");
		}
		parts.add(new MatchPart(text));
		return this;
	}

	/**
	 * Adds a newline character to the previously added text. 
	 * @return this builder
	 */
	public SearchLocationContextBuilder newline() {
		if (parts.isEmpty()) {
			throw new IllegalStateException("Cannot add a newline without first appending text");
		}
		Part last = parts.get(parts.size() - 1);
		last.text += '\n';
		return this;
	}

	/**
	 * Builds a {@link SearchLocationContext} using the text supplied via the {@code append}
	 * methods.
	 * @return the context
	 */
	public SearchLocationContext build() {
		return new SearchLocationContext(parts);
	}

	/**
	 * Returns true if no text has been added to this builder.
	 * @return true if no text has been added to this builder
	 */
	public boolean isEmpty() {
		return parts.isEmpty();
	}

	@Override
	public String toString() {
		return Json.toString(this);
	}
}
