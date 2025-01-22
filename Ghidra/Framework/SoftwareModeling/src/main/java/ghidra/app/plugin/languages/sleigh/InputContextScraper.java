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
package ghidra.app.plugin.languages.sleigh;

import java.util.*;

import ghidra.app.plugin.assembler.sleigh.sem.AssemblyDefaultContext;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;
import ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol;

/**
 * A class for scraping input contexts from a SLEIGH language to get all of the valid input contexts
 * that affect constructor selection
 * 
 */
public class InputContextScraper {
	private final SleighLanguage language;

	public InputContextScraper(SleighLanguage language) {
		this.language = language;
	}

	/**
	 * Get set of all valid input contexts that affect constructor selection.
	 * 
	 * <ol>
	 * <li>Start with mask of the language's default context
	 * <li>Scrape language for <code>globalset</code> context variables and OR their masks into our
	 * mask
	 * <li>Flip bits of our mask to get mask of context variables not used as input
	 * (local/transient)
	 * <li>Check constructor constraints and use mask to get values of relevant input context
	 * variables
	 * </ol>
	 */
	public Set<AssemblyPatternBlock> scrapeInputContexts() {
		// We don't care about the actual default values, just if a context variable HAS a default
		// value. It's possible for a local context variable to be set in the default context, but
		// doing so is questionable. It could be an input context variable in that case, so to
		// account for it, we start with the default context mask. Doing so ensures those variables
		// are included
		AssemblyPatternBlock defaultCtx = new AssemblyDefaultContext(language).getDefault();

		// Erase the values for posterity; we don't care about them at this point
		Arrays.fill(defaultCtx.getVals(), (byte) 0);

		GlobalSetScraper globalSetScraper = new GlobalSetScraper(defaultCtx);
		SleighLanguages.traverseConstructors(language, globalSetScraper);

		AssemblyPatternBlock nonInputCtxMask = globalSetScraper.getContextMask().invertMask();

		ConstraintScraper constraintScraper =
			new ConstraintScraper(nonInputCtxMask, language.getContextBaseRegister().getNumBytes());
		SleighLanguages.traverseConstructors(language, constraintScraper);

		return constraintScraper.getInputContexts();
	}

	private static class GlobalSetScraper implements ConstructorEntryVisitor {
		private AssemblyPatternBlock contextMask;

		GlobalSetScraper(AssemblyPatternBlock contextMask) {
			this.contextMask = contextMask;
		}

		public AssemblyPatternBlock getContextMask() {
			return contextMask;
		}

		@Override
		public int visit(SubtableSymbol subtable, DisjointPattern pattern, Constructor cons) {
			for (ContextChange chg : cons.getContextChanges()) {
				if (chg instanceof ContextCommit cc) {
					contextMask = contextMask.writeContextCommitMask(cc);
				}
			}
			return CONTINUE;
		}
	}

	private static class ConstraintScraper implements ConstructorEntryVisitor {
		private final AssemblyPatternBlock nonInputMask;
		private final AssemblyPatternBlock blankContext;
		private final Set<AssemblyPatternBlock> inputContexts;

		ConstraintScraper(AssemblyPatternBlock mask, int contextRegLen) {
			nonInputMask = mask;
			blankContext = AssemblyPatternBlock.fromLength(contextRegLen);
			inputContexts = new HashSet<>();
		}

		public Set<AssemblyPatternBlock> getInputContexts() {
			return inputContexts;
		}

		@Override
		public int visit(SubtableSymbol subtable, DisjointPattern pattern, Constructor cons) {
			AssemblyPatternBlock contextConstraint =
				AssemblyPatternBlock.fromPattern(pattern, pattern.getLength(true), true);

			if (contextConstraint.getMask().length > 0) {
				// Combine constraint with blank context to ensure generated context has no shifts
				AssemblyPatternBlock inputCtx =
					blankContext.combine(contextConstraint).maskOut(nonInputMask);

				// Filter out entirely undefined context
				if (inputCtx.getSpecificity() > 0) {
					inputContexts.add(inputCtx);
				}
			}
			return CONTINUE;
		}
	}
}
