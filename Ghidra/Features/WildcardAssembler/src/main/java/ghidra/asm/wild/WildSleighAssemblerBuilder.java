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

import java.util.*;

import ghidra.app.plugin.assembler.AssemblySelector;
import ghidra.app.plugin.assembler.sleigh.AbstractSleighAssemblerBuilder;
import ghidra.app.plugin.assembler.sleigh.SleighAssemblerBuilder;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblySentential;
import ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyResolutionFactory;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedBackfill;
import ghidra.app.plugin.assembler.sleigh.symbol.*;
import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;
import ghidra.asm.wild.grammars.WildAssemblyProduction;
import ghidra.asm.wild.sem.WildAssemblyResolutionFactory;
import ghidra.asm.wild.sem.WildAssemblyResolvedPatterns;
import ghidra.asm.wild.symbol.*;
import ghidra.program.model.listing.Program;

/**
 * The builder for wildcard-enabled assemblers.
 * 
 * <p>
 * Ideally, only one of these is created and cached per language, to save on the cost of building
 * the assembler. However, if heap space needs to be freed up, then the builder must be disposed.
 * 
 * <p>
 * This is based on the same abstract class as {@link SleighAssemblerBuilder}. See its documentation
 * for more information.
 */
public class WildSleighAssemblerBuilder
		extends AbstractSleighAssemblerBuilder<WildAssemblyResolvedPatterns, WildSleighAssembler> {

	protected final Map<AssemblySymbol, AssemblyNonTerminal> wildNTs = new HashMap<>();

	/**
	 * Construct a builder for the given language
	 * 
	 * <p>
	 * Once a builder is prepared for the given language, it can be used to build an assembler for
	 * any number of programs using that same language. Clients should take advantage of this to
	 * avoid re-incurring the steep cost of constructing an assembler for the same language.
	 * 
	 * @param lang the language
	 */
	public WildSleighAssemblerBuilder(SleighLanguage lang) {
		super(lang);
	}

	@Override
	protected AbstractAssemblyResolutionFactory< //
			WildAssemblyResolvedPatterns, AssemblyResolvedBackfill> newResolutionFactory() {
		return new WildAssemblyResolutionFactory();
	}

	protected WildAssemblyTerminal generateWildTerminal(AssemblySymbol t) {
		if (t instanceof AssemblyNonTerminal nt) {
			if ("instruction".equals(nt.getName())) {
				// Never allow full instruction to be wildcarded
				return null;
			}
			return new WildAssemblySubtableTerminal(nt.getName());
		}
		if (t instanceof AssemblyFixedNumericTerminal term) {
			return new WildAssemblyFixedNumericTerminal(term.getVal());
		}
		if (t instanceof AssemblyNumericMapTerminal term) {
			return new WildAssemblyNumericMapTerminal(term.getName(), term.getMap());
		}
		if (t instanceof AssemblyNumericTerminal term) {
			return new WildAssemblyNumericTerminal(term.getName(), term.getBitSize(),
				term.getSpace());
		}
		if (t instanceof AssemblyStringMapTerminal term) {
			return new WildAssemblyStringMapTerminal(term.getName(), term.getMap());
		}
		if (t instanceof AssemblyStringTerminal term && term.getDefiningSymbol() != null) {
			return new WildAssemblyStringTerminal(term.getString());
		}
		/**
		 * Exclude string terminals. These should be purely syntactic elements. Use of them as fixed
		 * literals, e.g., 1 or RAX, is an error on the spec's part.
		 */
		return null;
	}

	protected AssemblyNonTerminal createWildNonTerminal(AssemblySymbol s) {
		WildAssemblyTerminal wt = generateWildTerminal(s);
		if (wt == null) {
			return null;
		}
		WildAssemblyNonTerminal nt =
			new WildAssemblyNonTerminal("w`" + s.getName(), s.takesOperandIndex());
		grammar.addProduction(new WildAssemblyProduction(nt, new AssemblySentential<>(s)));
		grammar.addProduction(new WildAssemblyProduction(nt, new AssemblySentential<>(wt)));
		return nt;
	}

	protected AssemblyNonTerminal getOrCreateWildNonTerminal(AssemblySymbol s) {
		return wildNTs.computeIfAbsent(s, this::createWildNonTerminal);
	}

	protected AssemblySymbol maybeReplaceSymbol(AssemblySymbol s) {
		AssemblyNonTerminal nt = getOrCreateWildNonTerminal(s);
		if (nt == null) {
			return s;
		}
		return nt;
	}

	@Override
	protected void addProduction(AssemblyGrammar subgrammar, AssemblyNonTerminal lhs,
			AssemblySentential<AssemblyNonTerminal> rhs, DisjointPattern pattern, Constructor cons,
			List<Integer> indices) {
		// Don't call super. We want to replace the original production
		AssemblySentential<AssemblyNonTerminal> wildRhs = new AssemblySentential<>();
		for (AssemblySymbol sym : rhs.getSymbols()) {
			wildRhs.addSymbol(maybeReplaceSymbol(sym));
		}
		subgrammar.addProduction(lhs, wildRhs, pattern, cons, indices);
	}

	@Override
	protected WildSleighAssembler newAssembler(AssemblySelector selector) {
		return new WildSleighAssembler(factory, selector, lang, parser, defaultContext, ctxGraph);
	}

	@Override
	protected WildSleighAssembler newAssembler(AssemblySelector selector, Program program) {
		return new WildSleighAssembler(factory, selector, program, parser, defaultContext,
			ctxGraph);
	}
}
