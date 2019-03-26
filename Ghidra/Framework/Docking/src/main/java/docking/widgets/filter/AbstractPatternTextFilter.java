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
package docking.widgets.filter;

import java.util.regex.Pattern;

public abstract class AbstractPatternTextFilter implements TextFilter {

	protected final String filterText;
	private Pattern filterPattern;

	protected AbstractPatternTextFilter(String filterText) {
		this.filterText = filterText;
	}

	/**
	 * Subclasses must create the {@link Pattern} that will be used by this class when filtering.
	 * @return the pattern
	 */
	protected abstract Pattern createPattern();

	/**
	 * Subclasses implement this method for their usage of the given pattern (find vs. matches)
	 * 
	 * @param text the text to check against the pattern
	 * @param pattern the pattern used to match the text
	 * @return true if there is a match
	 */
	public abstract boolean matches(String text, Pattern pattern);

	@Override
	public String getFilterText() {
		return filterText;
	}

	@Override
	public boolean matches(String text) {
		if (text == null) {
			return false;
		}

		Pattern pattern = getFilterPattern();
		if (pattern == null) {
			return false;
		}

		return matches(text, pattern);
	}

	private Pattern getFilterPattern() {
		if (filterPattern == null) {
			filterPattern = createPattern();
		}
		return filterPattern;
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" + 
			"\tfilter: " + filterText + ",\n" +
			"\tpattern: " + getFilterPattern() + ",\n" +
		"}";
		//@formatter:on
	}
}
