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

import org.apache.commons.lang3.StringUtils;

/**
 * A text filter that uses a pattern and performs a 'matches' using that pattern.
 */
public abstract class MatchesPatternTextFilter extends AbstractPatternTextFilter {

	protected boolean caseSensitive;
	protected boolean allowGlobbing;

	public MatchesPatternTextFilter(String filterText, boolean caseSensitive,
			boolean allowGlobbing) {
		super(filterText);

		this.caseSensitive = caseSensitive;
		this.allowGlobbing = allowGlobbing;
	}

	protected boolean parentIsGlobEscape(MatchesPatternTextFilter parent) {

		if (allowGlobbing) {
			// Handle escaped glob characters.  A previous filter result that ends with an escape
			// character will not have correctly matched the items being filtered.  Thus, we cannot
			// be a sub filter such a parent filter.
			boolean endsWithEscapedGlob = StringUtils.endsWithAny(filterText, "\\?", "\\*");
			if (endsWithEscapedGlob) {
				// If the user type slow enough (to let the SwingUpdateManager run) in the filter
				// field, then the parent filter will end with a backslash.  If they user types fast
				// or pastes, then this will not be the case.
				if (parent.filterText.endsWith("\\")) {
					return true;
				}
			}
		}

		return false;
	}

	@Override
	public boolean matches(String text, Pattern pattern) {
		return pattern.matcher(text).matches();
	}

	@Override
	public int hashCode() {
		// not meant to put in hashing structures; the data for equals may change over time
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		if (!super.equals(obj)) {
			return false;
		}

		MatchesPatternTextFilter other = (MatchesPatternTextFilter) obj;
		if (allowGlobbing != other.allowGlobbing) {
			return false;
		}
		if (caseSensitive != other.caseSensitive) {
			return false;
		}
		return true;
	}

}
