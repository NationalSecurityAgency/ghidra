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
import ghidra.app.plugin.languages.sleigh.InputContextScraper;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.asm.wild.sem.DefaultWildAssemblyResolvedPatterns;
import ghidra.asm.wild.sem.WildAssemblyResolvedPatterns;
import ghidra.asm.wild.sem.WildAssemblyTreeResolver;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * An assembler implementation that allows for wildcard operands
 * 
 * <p>
 * Construct these using {@link WildSleighAssemblerBuilder}. 
 */
public class WildSleighAssembler extends AbstractSleighAssembler<WildAssemblyResolvedPatterns> {
	protected Set<AssemblyPatternBlock> inputContexts = null;

	protected WildSleighAssembler(
			AbstractAssemblyResolutionFactory<WildAssemblyResolvedPatterns, ?> factory,
			AssemblySelector selector, SleighLanguage lang, AssemblyParser parser,
			AssemblyDefaultContext defaultContext, AssemblyContextGraph ctxGraph) {
		super(factory, selector, lang, parser, defaultContext, ctxGraph);
	}

	protected WildSleighAssembler(
			AbstractAssemblyResolutionFactory<WildAssemblyResolvedPatterns, ?> factory,
			AssemblySelector selector, Program program, AssemblyParser parser,
			AssemblyDefaultContext defaultContext, AssemblyContextGraph ctxGraph) {
		super(factory, selector, program, parser, defaultContext, ctxGraph);
	}

	@Override
	protected WildAssemblyTreeResolver newResolver(Address at, AssemblyParseBranch tree,
			AssemblyPatternBlock ctx) {
		return new WildAssemblyTreeResolver(factory, lang, at, tree, ctx, ctxGraph);
	}

	@Override
	public AssemblyResolutionResults resolveTree(
			AssemblyParseResult parse, Address at, AssemblyPatternBlock ctx) {

		if (inputContexts == null) {
			InputContextScraper scraper = new InputContextScraper(lang);
			inputContexts = scraper.scrapeInputContexts();
		}

		AssemblyResolutionResults allResults = new AssemblyResolutionResults();

		// This could happen if a language doesn't use context
		// Just forward the (likely empty) ctx argument to resolveTree()
		if (inputContexts.isEmpty()) {
			allResults = super.resolveTree(parse, at, ctx);
			setContexts(allResults, ctx);
			return allResults;
		}

		for (AssemblyPatternBlock inputCtx : inputContexts) {
			AssemblyPatternBlock combinedCtx = inputCtx.combinePrecedence(ctx);
			AssemblyResolutionResults results = super.resolveTree(parse, at, combinedCtx);
			
			setContexts(results, combinedCtx);
			allResults.absorb(results);
		}
		return allResults;
	}
	
	private static void setContexts(AssemblyResolutionResults results, AssemblyPatternBlock ctx) {
		// Unspecified context bits are destroyed during assembly; restore them
		// All DefaultWildAssemblyResolvedPatterns in results argument should have identical context
		// TODO: Remove this hack. It's unclear where the best place is to keep/restore the original context
		for (AssemblyResolution res : results) {
			if (res instanceof DefaultWildAssemblyResolvedPatterns rp) {
				rp.setContext(ctx);
			}
		}
	}
}
