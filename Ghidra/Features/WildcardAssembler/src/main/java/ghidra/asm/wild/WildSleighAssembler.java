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
package ghidra.asm.wild;

import java.util.Set;

import ghidra.app.plugin.assembler.AssemblySelector;
import ghidra.app.plugin.assembler.sleigh.AbstractSleighAssembler;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParser;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.asm.wild.sem.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * An assembler implementation that allows for wildcard operands
 * 
 * <p>
 * Construct these using {@link WildSleighAssemblerBuilder}.
 */
public class WildSleighAssembler extends AbstractSleighAssembler<WildAssemblyResolvedPatterns> {
	protected final Set<AssemblyPatternBlock> inputContexts;

	protected WildSleighAssembler(
			AbstractAssemblyResolutionFactory<WildAssemblyResolvedPatterns, ?> factory,
			AssemblySelector selector, SleighLanguage lang, AssemblyParser parser,
			AssemblyDefaultContext defaultContext, Set<AssemblyPatternBlock> inputContexts,
			AssemblyContextGraph ctxGraph) {
		super(factory, selector, lang, parser, defaultContext, ctxGraph);
		this.inputContexts = inputContexts;
	}

	protected WildSleighAssembler(
			AbstractAssemblyResolutionFactory<WildAssemblyResolvedPatterns, ?> factory,
			AssemblySelector selector, Program program, AssemblyParser parser,
			AssemblyDefaultContext defaultContext, Set<AssemblyPatternBlock> inputContexts,
			AssemblyContextGraph ctxGraph) {
		super(factory, selector, program, parser, defaultContext, ctxGraph);
		this.inputContexts = inputContexts;
	}

	@Override
	protected WildAssemblyTreeResolver newResolver(Address at, AssemblyParseBranch tree,
			AssemblyPatternBlock ctx) {
		return new WildAssemblyTreeResolver(factory, lang, at, tree, ctx, ctxGraph);
	}

	@Override
	public AssemblyResolutionResults resolveTree(
			AssemblyParseResult parse, Address at, AssemblyPatternBlock ctx) {

		AssemblyResolutionResults allResults = new AssemblyResolutionResults();

		if (inputContexts.isEmpty()) {
			absorbWithContext(allResults, super.resolveTree(parse, at, ctx), ctx);
			return allResults;
		}

		for (AssemblyPatternBlock inputCtx : inputContexts) {
			AssemblyPatternBlock combinedCtx = inputCtx.assign(ctx);
			absorbWithContext(allResults, super.resolveTree(parse, at, combinedCtx), combinedCtx);
		}
		return allResults;
	}

	protected static void absorbWithContext(AssemblyResolutionResults allResults,
			AssemblyResolutionResults results, AssemblyPatternBlock ctx) {
		// Unspecified context bits are destroyed during assembly; restore them
		for (AssemblyResolution res : results) {
			allResults.add(switch (res) {
				case DefaultWildAssemblyResolvedPatterns rp -> rp.withContext(ctx);
				default -> res;
			});
		}
	}
}
