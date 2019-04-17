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

import java.util.Set;

import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch;

/**
 * A result of parsing a sentence
 * 
 * If the sentence was accepted, this yields a parse tree. If not, this describes the error and
 * provides suggestions to correct the error.
 */
public abstract class AssemblyParseResult implements Comparable<AssemblyParseResult> {

	/**
	 * Construct a successful parse result
	 * @param tree the tree output by the parser
	 */
	public static AssemblyParseAcceptResult accept(AssemblyParseBranch tree) {
		return new AssemblyParseAcceptResult(tree);
	}

	/**
	 * Construct an error parse result
	 * @param got the input buffer when the error occurred
	 * @param suggestions a subset of strings that would have allowed parsing to proceed
	 */
	public static AssemblyParseErrorResult error(String got, Set<String> suggestions) {
		return new AssemblyParseErrorResult(got, suggestions);
	}

	/**
	 * Check if the parse result is successful or an error
	 * @return true if the result describes an error
	 */
	public abstract boolean isError();

	@Override
	public int compareTo(AssemblyParseResult that) {
		return this.toString().compareTo(that.toString());
	}
}
