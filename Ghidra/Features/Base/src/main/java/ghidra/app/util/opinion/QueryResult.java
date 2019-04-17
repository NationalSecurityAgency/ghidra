/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.opinion;

import ghidra.program.model.lang.LanguageCompilerSpecPair;

public class QueryResult {
	public final LanguageCompilerSpecPair pair;
	public final boolean preferred;

	public QueryResult(LanguageCompilerSpecPair pair, boolean preferred) {
		this.pair = pair;
		this.preferred = preferred;
	}

	@Override
	public String toString() {
		return "query result: " + pair + " (" + (preferred ? "" : "not ") + "preferred)";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((pair == null) ? 0 : pair.hashCode());
		return result;
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
		QueryResult other = (QueryResult) obj;
		if (pair == null) {
			if (other.pair != null) {
				return false;
			}
		}
		else if (!pair.equals(other.pair)) {
			return false;
		}
		return true;
	}
}
