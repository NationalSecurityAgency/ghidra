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
package ghidra.dbg.util;

import java.util.List;
import java.util.Objects;

public class PathPattern implements PathPredicates {
	private final List<String> pattern;

	/**
	 * TODO: This can get more sophisticated if needed, but for now, I don't think we even need
	 * regular expressions. Either we care about a path element, or we don't.
	 * 
	 * <p>
	 * This takes a list of path keys as a means of matching paths. The empty key serves as a
	 * wildcard accepting all keys in that position, e.g., the following matches all elements within
	 * {@code Processes}:
	 * 
	 * <p>
	 * {@code List.of("Processes", "[]")}
	 * 
	 * <p>
	 * This should still be compatible with {@link PathUtils#parse(String)} and
	 * {@link PathUtils#toString(List)} allowing the last example to be expressed as
	 * {@code PathUtils.parse("Processes[]")}.
	 * 
	 * @param pattern a list of path elements
	 */
	public PathPattern(List<String> pattern) {
		this.pattern = List.copyOf(pattern);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof PathPattern)) {
			return false;
		}
		PathPattern that = (PathPattern) obj;
		return Objects.equals(this.pattern, that.pattern);
	}

	@Override
	public int hashCode() {
		return pattern.hashCode();
	}

	public static boolean keyMatches(String pat, String key) {
		if (key.equals(pat)) {
			return true;
		}
		if ("[]".equals(pat) && PathUtils.isIndex(key)) {
			return true;
		}
		if ("".equals(pat) && PathUtils.isName(pat)) {
			return true;
		}
		return false;
	}

	protected boolean matchesUpTo(List<String> path, int length) {
		for (int i = 0; i < length; i++) {
			if (!keyMatches(pattern.get(i), path.get(i))) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean matches(List<String> path) {
		if (path.size() != pattern.size()) {
			return false;
		}
		return matchesUpTo(path, path.size());
	}

	@Override
	public boolean successorCouldMatch(List<String> path) {
		if (path.size() > pattern.size()) {
			return false;
		}
		return matchesUpTo(path, path.size());
	}

	@Override
	public boolean ancestorMatches(List<String> path) {
		if (path.size() < pattern.size()) {
			return false;
		}
		return matchesUpTo(path, pattern.size());
	}
}
