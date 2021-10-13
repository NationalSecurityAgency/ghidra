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
package ghidra.app.plugin.core.navigation.locationreferences;

import java.util.ArrayList;
import java.util.List;

import generic.json.Json;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext.*;

/**
 * A builder for {@link LocationReferenceContext} objects.  Use {@link #append(String)} for normal
 * text pieces.  Use {@link #appendMatch(String)} for text that is meant to be rendered specially
 * by the context class.
 */
public class LocationReferenceContextBuilder {

	private List<Part> parts = new ArrayList<>();

	/**
	 * Appends the given text to this builder.
	 * @param text the text
	 * @return this builder
	 */
	public LocationReferenceContextBuilder append(String text) {
		if (text == null) {
			text = "";
		}
		parts.add(new BasicPart(text));
		return this;
	}

	/**
	 * Appends the given text to this builder.   This text represents a client-defined 'match' that
	 * will be rendered with markup when {@link LocationReferenceContext#getBoldMatchingText()} is
	 * called.
	 * @param text the text
	 * @return this builder
	 */
	public LocationReferenceContextBuilder appendMatch(String text) {
		if (text == null) {
			throw new NullPointerException("Match text cannot be null");
		}
		parts.add(new MatchPart(text));
		return this;
	}

	/**
	 * Builds a {@link LocationReferenceContext} using the text supplied via the {@code append}
	 * methods.
	 * @return the context
	 */
	public LocationReferenceContext build() {
		return new LocationReferenceContext(parts);
	}

	@Override
	public String toString() {
		return Json.toString(this);
	}
}
