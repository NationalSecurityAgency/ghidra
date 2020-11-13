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
package docking.widgets.autocomplete;

import java.util.Collection;

/**
 * A model to generate the suggested completions, given a viable prefix.
 *
 * @param <T> the type of suggestions this model gives.
 */
public interface AutocompletionModel<T> {
	/**
	 * Compute a collection of possible completions to the given text (prefix).
	 * @param text the prefix, i.e., the text to the left of the user's caret.
	 * @return a (possibly null or empty) list of suggested completions.
	 * 
	 * NOTE: there is no requirement that the returned items actually start with the given prefix;
	 * however, by default, the displayed text for the suggested item is inserted at the caret,
	 * without changing the surrounding text.
	 */
	public Collection<T> computeCompletions(String text);
}
