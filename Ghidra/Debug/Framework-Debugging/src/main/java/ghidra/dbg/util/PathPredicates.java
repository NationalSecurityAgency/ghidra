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

public interface PathPredicates {
	/**
	 * Check if the entire path passes
	 * 
	 * @param path the path to check
	 * @return true if it matches, false otherwise
	 */
	boolean matches(List<String> path);

	/**
	 * Check if the given path <em>could</em> have a matching successor
	 * 
	 * This essentially checks if the given path is a viable prefix to the matcher.
	 * 
	 * @implNote this method could become impractical for culling queries if we allow too
	 *           sophisticated of patterns. Notably, to allow an "any number of keys" pattern, e.g.,
	 *           akin to {@code /src/**{@literal /}*.c} in file system path matchers. Anything
	 *           starting with "src" could have a successor that matches.
	 * 
	 * 
	 * @param path the path (prefix) to check
	 * @return true if a successor could match, false otherwise
	 */
	boolean successorCouldMatch(List<String> path);

	/**
	 * Check if the given path has an ancestor that matches
	 * 
	 * @param path the path to check
	 * @return true if an ancestor matches, false otherwise
	 */
	boolean ancestorMatches(List<String> path);
}
