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
package ghidra.app.plugin.assembler.sleigh.parse;

import java.util.Collections;
import java.util.Set;

/**
 * An unsuccessful result from parsing
 */
public class AssemblyParseErrorResult extends AssemblyParseResult {
	private final String buffer;
	private final Set<String> suggestions;

	/**
	 * @see AssemblyParseResult#error(String, Set)
	 */
	protected AssemblyParseErrorResult(String got, Set<String> suggestions) {
		this.buffer = got;
		this.suggestions = suggestions;
	}

	@Override
	public boolean isError() {
		return true;
	}

	/**
	 * Get a description of the error
	 * @return a description
	 */
	public String describeError() {
		return "Syntax Error: Expected " + suggestions + ". Got " + buffer;
	}

	/**
	 * Get a set of suggested tokens that would have allowed parsing to continue
	 * @return the set
	 */
	public Set<String> getSuggestions() {
		return Collections.unmodifiableSet(suggestions);
	}

	/**
	 * Get the leftover contents of the input buffer when the error occurred
	 * @return
	 */
	public String getBuffer() {
		return buffer;
	}

	@Override
	public String toString() {
		return describeError();
	}
}
