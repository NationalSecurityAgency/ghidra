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

import java.util.*;

import org.apache.commons.collections4.MultiMapUtils;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;

import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblySentential;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParser;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.assembler.sleigh.symbol.*;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer.DbgCtx;
import ghidra.app.plugin.languages.sleigh.SleighLanguages;
import ghidra.app.plugin.languages.sleigh.SubtableEntryVisitor;
import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;
import ghidra.app.plugin.processors.sleigh.symbol.*;
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.app.plugin.processors.sleigh.template.HandleTpl;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.util.SystemUtilities;

public abstract class AbstractSleighAssemblerBuilder< //
		RP extends AssemblyResolvedPatterns, A extends GenericAssembler<RP>>
		implements GenericAssemblerBuilder<RP, A> {
	protected static final DbgTimer dbg =
		SystemUtilities.isInTestingBatchMode() ? DbgTimer.INACTIVE : DbgTimer.ACTIVE;

	protected final SleighLanguage lang;
	protected final AbstractAssemblyResolutionFactory<RP, ?> factory;
	protected AssemblyGrammar grammar;
	protected AssemblyDefaultContext defaultContext;
	protected AssemblyContextGraph ctxGraph;
	protected AssemblyParser parser;

	protected boolean generated = false;

	// A cache for symbols converted during grammar construction
	protected Map<String, AssemblySymbol> builtSymbols = new HashMap<>();

	public AbstractSleighAssemblerBuilder(SleighLanguage lang) {
		this.lang = lang;
		this.factory = newResolutionFactory();
	}

	protected abstract AbstractAssemblyResolutionFactory<RP, ?> newResolutionFactory();

	protected abstract A newAssembler(AssemblySelector selector);

	protected abstract A newAssembler(AssemblySelector selector,
			Program program);

	@Override
	public LanguageID getLanguageID() {
		return lang.getLanguageID();
	}

	@Override
	public SleighLanguage getLanguage() {
		return lang;
	}

	/**
	 * Do the actual work to construct an assembler from a SLEIGH language
	 * 
	 * @throws SleighException if there's an issue accessing the language
	 */
	protected void generateAssembler() throws SleighException {
		if (generated) {
			return;
		}
		generated = true;
		try {
			buildGrammar();
			grammar.verify();
			buildContext();
			buildContextGraph();
			buildParser();
		}
		catch (SleighException e) {
			// Not sure this can actually happen here
			throw e;
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public A getAssembler(AssemblySelector selector) {
		generateAssembler();
		return newAssembler(selector);
	}

	@Override
	public A getAssembler(AssemblySelector selector, Program program) {
		generateAssembler();
		return newAssembler(selector, program);
	}

	/**
	 * Invert a varnode list to a map suitable for use with {@link AssemblyStringMapTerminal}
	 * 
	 * @param vnlist the varnode list symbol
	 * @return the inverted string map
	 */
	protected MultiValuedMap<String, Integer> invVarnodeList(VarnodeListSymbol vnlist) {
		MultiValuedMap<String, Integer> result = new HashSetValuedHashMap<>();
		int index = -1;
		for (VarnodeSymbol vnsym : vnlist.getVarnodeTable()) {
			index++;
			if (vnsym != null) {
				// nulls are _ in the spec, meaning the index is undefined.
				result.put(vnsym.getName(), index);
			}
		}
		return MultiMapUtils.unmodifiableMultiValuedMap(result);
	}

	/**
	 * Invert a value map to a map suitable for use with {@link AssemblyNumericMapTerminal}
	 * 
	 * @param vm the value map symbol
	 * @return the inverted numeric map
	 */
	protected Map<Long, Integer> invValueMap(ValueMapSymbol vm) {
		Map<Long, Integer> result = new HashMap<>();
		List<Long> map = vm.getMap();
		for (int i = 0; i < map.size(); i++) {
			long v = map.get(i);
			result.put(v, i);
		}
		return Collections.unmodifiableMap(result);
	}

	/**
	 * Invert a name table to a map suitable for use with {@link AssemblyStringMapTerminal}
	 * 
	 * @param ns the name symbol
	 * @return the inverted string map
	 */
	protected MultiValuedMap<String, Integer> invNameSymbol(NameSymbol ns) {
		MultiValuedMap<String, Integer> result = new HashSetValuedHashMap<>();
		int index = -1;
		for (String name : ns.getNameTable()) {
			index++;
			if (name != null) {
				result.put(name, index);
			}
		}
		return MultiMapUtils.unmodifiableMultiValuedMap(result);
	}

	/**
	 * Convert the given operand symbol to an {@link AssemblySymbol}
	 * 
	 * <p>
	 * For subtables, this results in a non-terminal, for all others, the result in a terminal.
	 * 
	 * @param cons the constructor to which the operand belongs
	 * @param opsym the operand symbol to convert
	 * @return the converted assembly grammar symbol
	 */
	protected AssemblySymbol getSymbolFor(Constructor cons, OperandSymbol opsym) {
		TripleSymbol defsym = opsym.getDefiningSymbol();
		// If the symbol has no defining symbol, that means the name is only valid in the local
		// scope. We must keep them unique.
		String name;
		if (defsym == null) {
			name = cons.getParent().getName() + ":" + opsym.getName();
		}
		else {
			name = opsym.getName();
		}
		AssemblySymbol built = builtSymbols.get(name);
		if (built != null) {
			return built;
		}
		if (defsym == null) {
			HandleTpl htpl = getHandleTpl(cons, opsym);
			built = htpl == null ? new AssemblyNumericTerminal(name, 0, null)
					: new AssemblyNumericTerminal(name, htpl.getSize(), htpl.getAddressSpace());
		}
		else if (defsym instanceof SubtableSymbol) {
			built = new AssemblyNonTerminal(name);
		}
		else if (defsym instanceof VarnodeListSymbol vnListSym) {
			built = new AssemblyStringMapTerminal(name, invVarnodeList(vnListSym));
		}
		else if (defsym instanceof VarnodeSymbol vnSym) {
			built = new AssemblyStringTerminal(name, vnSym);
			// Does this need to consume an operand? It seems not.
		}
		else if (defsym instanceof ValueMapSymbol vnMapSym) {
			built = new AssemblyNumericMapTerminal(name, invValueMap(vnMapSym));
		}
		else if (defsym instanceof NameSymbol nameSym) {
			built = new AssemblyStringMapTerminal(name, invNameSymbol(nameSym));
		}
		else {
			throw new RuntimeException("Unknown symbol for " + name + ": " + defsym);
		}
		builtSymbols.put(name, built);
		return built;
	}

	/**
	 * Obtain the p-code result handle for the given operand
	 * 
	 * <p>
	 * This handles a special case, where a constructor prints just one operand and exports that
	 * same operand, often with an explicit size, or as an address in a given space. In such cases,
	 * the listing displays that operand according to that exported size.
	 * 
	 * <p>
	 * For assembly, this gives a few opportunities: 1) We can/must ensure the specified value fits,
	 * by checking the size. 2) We can/must mask the goal when solving the defining pattern
	 * expression for the operand. 3)) We can/must check that a label's address space matches that
	 * represented by the operand, when used for a numeric terminal.
	 * 
	 * @param cons the constructor from which the production is being derived
	 * @param opsym the operand symbol corresponding to the grammatical symbol, whose size we wish
	 *            to determine.
	 * @return the size of the operand in bits
	 */
	protected HandleTpl getHandleTpl(Constructor cons, OperandSymbol opsym) {
		ConstructTpl ctpl = cons.getTempl();
		if (null == ctpl) {
			// No pcode, no size specification
			return null;
		}
		HandleTpl htpl = ctpl.getResult();
		if (null == htpl) {
			// If nothing is exported, the size is unspecified
			return null;
		}
		if (opsym.getIndex() != htpl.getOffsetOperandIndex()) {
			// If the export is not of the same operand, it does not specify its size
			return null;
		}
		return htpl;
	}

	/**
	 * Build a portion of the grammar representing a table of constructors
	 * 
	 * @param subtable the table
	 * @return the partial grammar
	 */
	protected AssemblyGrammar buildSubGrammar(SubtableSymbol subtable) {
		final AssemblyGrammar subgrammar = new AssemblyGrammar(factory);
		final AssemblyNonTerminal lhs = new AssemblyNonTerminal(subtable.getName());
		SleighLanguages.traverseConstructors(subtable, new SubtableEntryVisitor() {
			@Override
			public int visit(DisjointPattern pattern, Constructor cons) {
				AssemblySentential<AssemblyNonTerminal> rhs = new AssemblySentential<>();
				List<Integer> indices = new ArrayList<>();
				for (String str : cons.getPrintPieces()) {
					if (str.length() != 0) {
						if (str.charAt(0) == '\n') {
							int index = str.charAt(1) - 'A';
							OperandSymbol opsym = cons.getOperand(index);
							AssemblySymbol sym = getSymbolFor(cons, opsym);
							if (sym.takesOperandIndex()) {
								indices.add(index);
							}
							rhs.addSymbol(sym);
						}
						else {
							rhs.addSeparators(str);
						}
					}
				}
				addProduction(subgrammar, lhs, rhs, pattern, cons, indices);
				return CONTINUE;
			}
		});
		return subgrammar;
	}

	/**
	 * Extension point: Allows a chance to modify or derive a new production from a given one.
	 * 
	 * @param subgrammar the sub-grammar for the sub-table symbol being processed
	 * @see AssemblyGrammar#addProduction(AssemblyNonTerminal, AssemblySentential, DisjointPattern,
	 *      Constructor, List)
	 */
	protected void addProduction(AssemblyGrammar subgrammar, AssemblyNonTerminal lhs,
			AssemblySentential<AssemblyNonTerminal> rhs, DisjointPattern pattern, Constructor cons,
			List<Integer> indices) {
		subgrammar.addProduction(lhs, rhs, pattern, cons, indices);
	}

	/**
	 * Build the full grammar for the language
	 */
	protected void buildGrammar() {
		try (DbgCtx dc = dbg.start("Building grammar")) {
			grammar = new AssemblyGrammar(factory);
			for (Symbol sym : lang.getSymbolTable().getSymbolList()) {
				if (sym instanceof SubtableSymbol) {
					SubtableSymbol subtable = (SubtableSymbol) sym;
					grammar.combine(buildSubGrammar(subtable));
				}
				else if (sym instanceof VarnodeSymbol) {
					// Ignore. This just becomes a string terminal
				}
				else if (sym instanceof StartSymbol) {
					// Ignore. We handle inst_start in semantic processing
				}
				else if (sym instanceof EndSymbol) {
					// Ignore. We handle inst_next in semantic processing
				}

				else if (sym instanceof Next2Symbol) {
					// Ignore. We handle inst_next2 in semantic processing
				}
				else if (sym instanceof UseropSymbol) {
					// Ignore. We don't do pcode.
				}
				else if (sym instanceof OperandSymbol) {
					// Ignore. These are terminals, or will be produced by their defining symbols
				}
				else if (sym instanceof ValueSymbol) {
					// Ignore. These are now terminals
				}
				else {
					throw new RuntimeException("Unexpected type: " + sym.getClass());
				}
			}
			grammar.setStartName("instruction");
		}
	}

	/**
	 * Build the default context for the language
	 */
	protected void buildContext() {
		defaultContext = new AssemblyDefaultContext(lang);
	}

	/**
	 * Build the context transition graph for the language
	 */
	protected void buildContextGraph() {
		try (DbgCtx dc = dbg.start("Building context graph")) {
			ctxGraph = new AssemblyContextGraph(factory, lang, grammar);
		}
	}

	/**
	 * Build the parser for the language
	 */
	protected void buildParser() {
		try (DbgCtx dc = dbg.start("Building parser")) {
			parser = new AssemblyParser(grammar);
		}
	}

	/**
	 * Get the built grammar for the language
	 * 
	 * @return the grammar
	 */
	protected AssemblyGrammar getGrammar() {
		return grammar;
	}

	/**
	 * Get the built parser for the language
	 * 
	 * @return the parser
	 */
	protected AssemblyParser getParser() {
		return parser;
	}
}
