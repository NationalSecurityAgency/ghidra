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
package ghidra.app.plugin.assembler.sleigh.sem;

import java.util.stream.Stream;

import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseNumericToken;
import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;

/**
 * The generator of {@link AssemblyOperandState} for a hidden value operand
 * 
 * <p>
 * In short, this does nothing, except to hold the place of the operand for diagnostics. Likely, the
 * "hidden" operand appears in the defining expression of a temporary symbol used in the print
 * pieces.
 */
public class AssemblyNopStateGenerator
		extends AbstractAssemblyStateGenerator<AssemblyParseNumericToken> {
	protected final OperandSymbol opSym;

	/**
	 * Construct the hidden value operand state generator
	 * 
	 * @param resolver the resolver
	 * @param opSym the operand symbol
	 * @param fromLeft the accumulated patterns from the left sibling or parent
	 */
	public AssemblyNopStateGenerator(AssemblyTreeResolver resolver, OperandSymbol opSym,
			AssemblyResolvedPatterns fromLeft) {
		super(resolver, null, fromLeft);
		this.opSym = opSym;
	}

	@Override
	public Stream<AssemblyGeneratedPrototype> generate(GeneratorContext gc) {
		gc.dbg("Generating NOP for " + opSym);
		return Stream.of(
			new AssemblyGeneratedPrototype(new AssemblyNopState(resolver, gc.path, gc.shift, opSym),
				fromLeft));
	}
}
