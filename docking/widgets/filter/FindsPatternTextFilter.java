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

/**
 * A text filter that uses a pattern and performs a 'find' using that pattern.
 */
public class FindsPatternTextFilter extends AbstractPatternTextFilter {

	public FindsPatternTextFilter(String filterText) {
		super(filterText);
	}

	@Override
	protected Pattern createPattern() {
		try {
			Pattern pattern = Pattern.compile(filterText, Pattern.DOTALL);
			return pattern;
		}
		catch (Exception e) {
			// This can happen as the user is typing their regex; not sure what else we can do.
			// The net effect is that the filter will appear to do nothing.
			return null;
		}
	}

	@Override
	public boolean matches(String text, Pattern pattern) {
		return pattern.matcher(text).find();
	}

	@Override
	public boolean isSubFilterOf(TextFilter parentFilter) {
		if (!(parentFilter instanceof FindsPatternTextFilter)) {
			return false;
		}

		//
		// This can be very tricky, so only attempt simple pattern comparison: we have to 
		// start with the given pattern and our new text can only use simple regex characters
		//
		FindsPatternTextFilter other = (FindsPatternTextFilter) parentFilter;
		String parent = other.filterText;
		String child = filterText;
		if (!child.startsWith(parent)) {
			return false;
		}

		// only allow simple globbing characters (in order to avoid complex things like look ahead
		// and look behind
		boolean isSubFilter = areAllCharactersSimpleEnough(child.substring(parent.length()));
		return isSubFilter;
	}

	// Note: this choice of characters is seriously arbitrary, decided through manual testing.  If
	//       we encounter failure cases in the wild, then we may wish to simplify this even 
	//       further to letters/digits and perhaps simple globbing characters (like * and ?).  The
	//       hope is that the 'startsWith' criteria is enough to prevent most catastrophes
	private boolean areAllCharactersSimpleEnough(String s) {
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c >= 0x20 && c <= 0x5A) {
				// 'Space' through upper-case Z
				continue;
			}

			if (c >= 0x5F && c <= 0x7A) {
				// 'Underscore' through lower-case z
				continue;
			}

			return false;
		}
		return true;
	}
}
