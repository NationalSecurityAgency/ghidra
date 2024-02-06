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
package ghidra.asm.wild.tree;

import java.io.PrintStream;

import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseTreeNode;

public class WildAssemblyParseHiddenNode extends AssemblyParseTreeNode {
	public final String wildcard;

	public WildAssemblyParseHiddenNode(AssemblyGrammar grammar, String wildcard) {
		super(grammar);
		this.wildcard = wildcard;
	}

	@Override
	public AssemblySymbol getSym() {
		return null;
	}

	@Override
	protected void print(PrintStream out, String indent) {
		out.print("<wild-hidden>");
	}

	@Override
	public String generateString() {
		return "";
	}
}
