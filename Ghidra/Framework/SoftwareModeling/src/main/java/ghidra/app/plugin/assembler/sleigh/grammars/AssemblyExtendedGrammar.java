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
package ghidra.app.plugin.assembler.sleigh.grammars;

import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyExtendedNonTerminal;

/**
 * Defines an "extended" grammar
 * 
 * "Extended grammar" as in a grammar extended with state numbers from an LR0 parser.
 * See <a href="http://web.cs.dal.ca/~sjackson/lalr1.html">LALR(1) Parsing</a> from Stephen Jackson
 * of Dalhousie University, Halifax, Nova Scotia, Canada.
 */
public class AssemblyExtendedGrammar
		extends AbstractAssemblyGrammar<AssemblyExtendedNonTerminal, AssemblyExtendedProduction> {

	@Override
	protected AssemblyExtendedProduction newProduction(AssemblyExtendedNonTerminal lhs,
			AssemblySentential<AssemblyExtendedNonTerminal> rhs) {
		throw new UnsupportedOperationException("Please construct extended productions yourself");
	}
}
