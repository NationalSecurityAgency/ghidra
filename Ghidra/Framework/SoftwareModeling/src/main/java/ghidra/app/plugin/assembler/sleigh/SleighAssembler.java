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
package ghidra.app.plugin.assembler.sleigh;

import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParser;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * An {@link Assembler} for a {@link SleighLanguage}.
 * 
 * <p>
 * For documentation on how the SLEIGH assembler works, see {@link SleighAssemblerBuilder}. To use
 * the assembler, please use {@link Assemblers#getAssembler(Program)} or similar.
 */
public class SleighAssembler extends AbstractSleighAssembler<AssemblyResolvedPatterns>
		implements Assembler {

	/**
	 * Construct a SleighAssembler.
	 * 
	 * @param selector a method of selecting one result from many
	 * @param program the program to bind to (must have same language as parser)
	 * @param parser the parser for the SLEIGH language
	 * @param defaultContext the default context for the language
	 * @param ctxGraph the context graph
	 */
	protected SleighAssembler(
			AbstractAssemblyResolutionFactory<AssemblyResolvedPatterns, ?> factory,
			AssemblySelector selector, Program program, AssemblyParser parser,
			AssemblyDefaultContext defaultContext, AssemblyContextGraph ctxGraph) {
		super(factory, selector, program, parser, defaultContext, ctxGraph);
	}

	/**
	 * Construct a SleighAssembler.
	 * 
	 * <p>
	 * <b>NOTE:</b> This variant does not permit {@link #assemble(Address, String...)}.
	 * 
	 * @param selector a method of selecting one result from many
	 * @param lang the SLEIGH language (must be same as to create the parser)
	 * @param parser the parser for the SLEIGH language
	 * @param defaultContext the default context for the language
	 * @param ctxGraph the context graph
	 */
	protected SleighAssembler(
			AbstractAssemblyResolutionFactory<AssemblyResolvedPatterns, ?> factory,
			AssemblySelector selector, SleighLanguage lang, AssemblyParser parser,
			AssemblyDefaultContext defaultContext, AssemblyContextGraph ctxGraph) {
		super(factory, selector, lang, parser, defaultContext, ctxGraph);
	}

	@Override
	protected AssemblyTreeResolver newResolver(Address at, AssemblyParseBranch tree,
			AssemblyPatternBlock ctx) {
		return new AssemblyTreeResolver(factory, lang, at, tree, ctx, ctxGraph);
	}
}
