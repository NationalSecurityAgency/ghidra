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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch;

/**
 * A successful result from parsing
 */
public class AssemblyParseAcceptResult extends AssemblyParseResult {
	private final AssemblyParseBranch tree;

	/**
	 * @see AssemblyParseResult#accept(AssemblyParseBranch)
	 */
	protected AssemblyParseAcceptResult(AssemblyParseBranch tree) {
		this.tree = tree;
	}

	@Override
	public boolean isError() {
		return false;
	}

	/**
	 * Get the tree
	 * @return the tree
	 */
	public AssemblyParseBranch getTree() {
		return tree;
	}

	@Override
	public String toString() {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		tree.print(new PrintStream(baos));
		return new String(baos.toByteArray());
	}
}
