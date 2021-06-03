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

import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;

import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblySentential;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParser;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyContextGraph;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyDefaultContext;
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

/**
 * An {@link AssemblerBuilder} capable of supporting almost any {@link SleighLanguage}
 * 
 * To build an assembler, please use a static method of the {@link Assemblers} class.
 * 
 * SLEIGH-based assembly is a bit of an experimental feature at this time. Nevertheless, it seems to
 * have come along quite nicely. It's not quite as fast as disassembly, since after all, that's what
 * SLEIGH was designed to do.
 * 
 * Overall, the method is fairly simple, though its implementation is a bit more complex. First, we
 * gather every pair of pattern and constructor by traversing the decision tree used by disassembly.
 * We then use the "print pieces" to construct a context-free grammar. Each production is associated
 * with the one-or-more constructors with the same sequence of print pieces. We then build a LALR(1)
 * parser for the generated grammar. This now constitutes a generic parser for the given language.
 * Note that this step takes some time, and may be better suited as a build-time step. Because
 * SLEIGH specifications are not generally concerned with eliminating ambiguity of printed
 * instructions (rather, it only does so for instruction bytes), we must consider that the grammar
 * could be ambiguous. To handle this, the action/goto table is permitted multiple entries per cell,
 * and we allow backtracking. There are also cases where tokens are not actually separated by
 * spaces. For example, in the {@code ia.sinc} file, there is JMP ... and J^cc, meaning, the lexer
 * must consider J as a token as well as JMP, introducing another source of possible backtracking.
 * Despite that, parsing is completed fairly quickly.
 * 
 * To assemble, we first parse the textual instruction, yielding zero or more parse trees. No parse
 * trees implies an error. For each parse tree, we attempt to resolve the instruction bytes,
 * starting at the leaves and working upwards while tracking and solving context changes. The
 * context changes must be considered in reverse. We <em>read</em> the context register of the
 * children (a disassembler would write). We then assume there is at most one variable in the
 * expression, solve for it, and <em>write</em> the solution to the appropriate field (a
 * disassembler would read). If no solution exists, a semantic error is logged. Since it's possible
 * a production in the parse tree is associated with multiple constructors, different combinations
 * of constructors are explored as we move upward in the tree. If all possible combinations yield
 * semantic errors, then the overall result is an error.
 * 
 * Some productions are "purely recursive," e.g., {@code :^instruction} lines in the SLEIGH. These
 * are ignored during parser construction. Let such a production be given as I =&gt; I. When resolving
 * the parse tree to bytes, and we encounter a production with I on the left hand side, we then
 * consider the possible application of the production I =&gt; I and its consequential constructors.
 * Ideally, we could repeat this indefinitely, stopping when all further applications result in
 * semantic errors; however, there is no guarantee in the SLEIGH specification that such an
 * algorithm will actually halt, so a maximum number (default of 1) of applications are attempted.
 * 
 * After all the context changes and operands are resolved, we apply the constructor patterns and
 * proceed up the tree. Thus, each branch yields zero or more "resolved constructors," which each
 * specify two masked blocks of data: one for the instruction, and one for the context. These are
 * passed up to the parent production, which, having obtained results from all its children,
 * attempts to apply the corresponding constructors.
 * 
 * Once we've resolved the root node, any resolved constructors returned are taken as successfully
 * assembled instruction bytes. If applicable, the corresponding context registers are compared to
 * the context at the target address in the program and filtered for compatibility.
 */
public class SleighAssemblerBuilder implements AssemblerBuilder {
	protected static final DbgTimer dbg = SystemUtilities.isInTestingBatchMode() ? DbgTimer.INACTIVE : DbgTimer.ACTIVE;

	protected SleighLanguage lang;
	protected AssemblyGrammar grammar;
	protected AssemblyDefaultContext defaultContext;
	protected AssemblyContextGraph ctxGraph;
	protected AssemblyParser parser;

	protected boolean generated = false;

	// A cache for symbols converted during grammar construction
	protected Map<String, AssemblySymbol> builtSymbols = new HashMap<>();

	/**
	 * Construct an assembler builder for the given SLEIGH language
	 * 
	 * @param lang the language
	 */
	public SleighAssemblerBuilder(SleighLanguage lang) {
		this.lang = lang;
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
	public LanguageID getLanguageID() {
		return lang.getLanguageID();
	}

	@Override
	public SleighLanguage getLanguage() {
		return lang;
	}

	@Override
	public SleighAssembler getAssembler(AssemblySelector selector) {
		generateAssembler();
		SleighAssembler asm = new SleighAssembler(selector, lang, parser, defaultContext, ctxGraph);
		return asm;
	}

	@Override
	public SleighAssembler getAssembler(AssemblySelector selector, Program program) {
		generateAssembler();
		return new SleighAssembler(selector, program, parser, defaultContext, ctxGraph);
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
		return result;
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
		return result;
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
		return result;
	}

	/**
	 * Convert the given operand symbol to an {@link AssemblySymbol}
	 * 
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
			built = new AssemblyNumericTerminal(name, getBitSize(cons, opsym));
		}
		else if (defsym instanceof SubtableSymbol) {
			built = new AssemblyNonTerminal(name);
		}
		else if (defsym instanceof VarnodeListSymbol) {
			built = new AssemblyStringMapTerminal(name, invVarnodeList((VarnodeListSymbol) defsym));
		}
		else if (defsym instanceof VarnodeSymbol) {
			built = new AssemblyStringTerminal(name);
			// Does this need to consume an operand? It seems not.
		}
		else if (defsym instanceof ValueMapSymbol) {
			built = new AssemblyNumericMapTerminal(name, invValueMap((ValueMapSymbol) defsym));
		}
		else if (defsym instanceof NameSymbol) {
			built = new AssemblyStringMapTerminal(name, invNameSymbol((NameSymbol) defsym));
		}
		else {
			throw new RuntimeException("Unknown symbol for " + name + ": " + defsym);
		}
		builtSymbols.put(name, built);
		return built;
	}

	/**
	 * Obtain the size in bits of a textual operand.
	 * 
	 * This is a little odd, since the variables in pattern expressions do not have an explicit
	 * size. However, the value exported by a constructor's pCode may have an explicit size given
	 * (in bytes). Thus, there is a special case, where a constructor prints just one operand and
	 * exports that same operand with an explicit size. In that case, the size of the operand is
	 * printed according to that exported size.
	 * 
	 * For disassembly, this information is used simply to truncate the bits before they are
	 * displayed. For assembly, we must do two things: 1) Ensure that the provided value fits in the
	 * given size, and 2) Mask the goal when solving the pattern expression for the operand.
	 * 
	 * @param cons the constructor from which the production is being derived
	 * @param opsym the operand symbol corresponding to the grammatical symbol, whose size we wish
	 *            to determine.
	 * @return the size of the operand in bits
	 */
	protected int getBitSize(Constructor cons, OperandSymbol opsym) {
		ConstructTpl ctpl = cons.getTempl();
		if (null == ctpl) {
			// No pcode, no size specification
			return 0;
		}
		HandleTpl htpl = ctpl.getResult();
		if (null == htpl) {
			// If nothing is exported, the size is unspecified
			return 0;
		}
		if (opsym.getIndex() != htpl.getOffsetOperandIndex()) {
			// If the export is not of the same operand, it does not specify its size
			return 0;
		}
		return htpl.getSize();
	}

	/**
	 * Build a portion of the grammar representing a table of constructors
	 * 
	 * @param subtable the table
	 * @return the partial grammar
	 */
	protected AssemblyGrammar buildSubGrammar(SubtableSymbol subtable) {
		final AssemblyGrammar subgrammar = new AssemblyGrammar();
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
							rhs.add(sym);
						}
						else {
							String tstr = str.trim();
							if (tstr.equals("")) {
								rhs.addWS();
							}
							else {
								char first = tstr.charAt(0);
								if (!str.startsWith(tstr)) {
									rhs.addWS();
								}
								if (!Character.isLetterOrDigit(first)) {
									rhs.addWS();
								}
								rhs.add(new AssemblyStringTerminal(str.trim()));
								char last = tstr.charAt(tstr.length() - 1);
								if (!str.endsWith(tstr)) {
									rhs.addWS();
								}
								if (!Character.isLetterOrDigit(last)) {
									rhs.addWS();
								}
							}
						}
					}
				}
				subgrammar.addProduction(lhs, rhs, pattern, cons, indices);
				return CONTINUE;
			}
		});
		return subgrammar;
	}

	/**
	 * Build the full grammar for the language
	 */
	protected void buildGrammar() {
		try (DbgCtx dc = dbg.start("Building grammar")) {
			grammar = new AssemblyGrammar();
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
				else if (sym instanceof UseropSymbol) {
					// Ignore. We don't do pcode.
				}
				else if (sym instanceof OperandSymbol) {
					// Ignore. These are terminals, or will be produced by there defining symbol
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
			ctxGraph = new AssemblyContextGraph(lang, grammar);
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
