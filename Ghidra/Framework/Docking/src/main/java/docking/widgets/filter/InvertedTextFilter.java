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

import java.util.Objects;

public class InvertedTextFilter implements TextFilter {

	private final TextFilter filter;

	public InvertedTextFilter(TextFilter filter) {
		this.filter = filter;
	}

	@Override
	public boolean isSubFilterOf(TextFilter textFilter) {
		// Inverted filters can't add back data that has already been filtered out
		return false;
	}

	@Override
	public boolean matches(String text) {
		return !filter.matches(text);
	}

	@Override
	public String getFilterText() {
		return filter.getFilterText();
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

		InvertedTextFilter other = (InvertedTextFilter) obj;
		if (!Objects.equals(filter, other.filter)) {
			return false;
		}
		return true;
	}
}
