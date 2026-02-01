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
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseTreeNode;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.symbol.*;
import ghidra.asm.wild.grammars.WildAssemblyProduction;
import ghidra.asm.wild.symbol.*;
import ghidra.asm.wild.tree.WildAssemblyParseHiddenNode;
import ghidra.asm.wild.tree.WildAssemblyParseToken;
import ghidra.program.model.address.Address;

public class WildAssemblyTreeResolver
		extends AbstractAssemblyTreeResolver<WildAssemblyResolvedPatterns> {

	public WildAssemblyTreeResolver(
			AbstractAssemblyResolutionFactory<WildAssemblyResolvedPatterns, ?> factory,
			SleighLanguage lang, Address at, AssemblyParseBranch tree, AssemblyPatternBlock context,
			AssemblyContextGraph ctxGraph) {
		super(factory, lang, at, tree, context, ctxGraph);
	}

	protected AbstractAssemblyStateGenerator<?> getWildHiddenStateGenerator(OperandSymbol opSym,
			String wildcard, AssemblyResolvedPatterns fromLeft) {
		TripleSymbol defSym = opSym.getDefiningSymbol();
		if (defSym instanceof SubtableSymbol subtable) {
			return new WildAssemblyConstructStateGenerator(this, subtable, wildcard, fromLeft);
		}
		return new WildAssemblyNopStateGenerator(this, null, opSym, wildcard, fromLeft);
	}

	@Override
	protected AbstractAssemblyStateGenerator<?> getStateGenerator(OperandSymbol opSym,
			AssemblyParseTreeNode node, AssemblyResolvedPatterns fromLeft) {
		if (node instanceof WildAssemblyParseHiddenNode hidden) {
			return getWildHiddenStateGenerator(opSym, hidden.wildcard, fromLeft);
		}
		if (node instanceof AssemblyParseBranch branch && !branch.isConstructor()) {
			if (branch.getProduction() instanceof WildAssemblyProduction) {
				assert branch.getSubstitutions().size() == 1;
				return getStateGenerator(opSym, branch.getSubstitution(0), fromLeft);
			}
		}
		if (!(node instanceof WildAssemblyParseToken token)) {
			return super.getStateGenerator(opSym, node, fromLeft);
		}
		if (node.getSym() instanceof WildAssemblySubtableTerminal term) {
			return getWildHiddenStateGenerator(opSym, token.wildcardName(), fromLeft);
		}
		if (node.getSym() instanceof WildAssemblyNumericMapTerminal term) {
			return new WildAssemblyNumericMapStateGenerator(this, token, opSym, term.map, fromLeft);
		}
		if (node.getSym() instanceof WildAssemblyStringMapTerminal term) {
			return new WildAssemblyStringMapStateGenerator(this, token, opSym, term.map, fromLeft);
		}
		if (node.getSym() instanceof WildAssemblyStringTerminal term) {
			return new WildAssemblyStringStateGenerator(this, token, opSym, term.str, fromLeft);
		}
		if (node.getSym() instanceof WildAssemblyFixedNumericTerminal term) {
			return new WildAssemblyFixedNumericStateGenerator(this, token, opSym, term.val,
				fromLeft);
		}
		if (node.getSym() instanceof WildAssemblyNumericTerminal term) {
			return new WildAssemblyNumericStateGenerator(this, token, opSym, token.wildcardName(),
				fromLeft);
		}
		return super.getStateGenerator(opSym, node, fromLeft);
	}
}
