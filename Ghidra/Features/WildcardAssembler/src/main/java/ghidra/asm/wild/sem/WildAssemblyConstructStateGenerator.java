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
package ghidra.asm.wild.sem;

import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseTreeNode;
import ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol;
import ghidra.asm.wild.tree.WildAssemblyParseHiddenNode;

public class WildAssemblyConstructStateGenerator extends AssemblyHiddenConstructStateGenerator {
	protected final String wildcard;

	public WildAssemblyConstructStateGenerator(AbstractAssemblyTreeResolver<?> resolver,
			SubtableSymbol subtableSym, String wildcard, AssemblyResolvedPatterns fromLeft) {
		super(resolver, subtableSym, fromLeft);
		this.wildcard = wildcard;
	}

	@Override
	protected AssemblyParseTreeNode getFiller() {
		return new WildAssemblyParseHiddenNode(resolver.getGrammar(), wildcard);
	}
}
