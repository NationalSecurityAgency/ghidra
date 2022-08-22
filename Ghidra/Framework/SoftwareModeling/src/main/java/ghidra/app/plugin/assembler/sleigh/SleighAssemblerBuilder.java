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

/**
 * An {@link AssemblerBuilder} capable of supporting almost any {@link SleighLanguage}
 * 
 * <p>
 * To build an assembler, please use a static method of the {@link Assemblers} class.
 * 
 * <p>
 * SLEIGH-based assembly is a bit temperamental, since it essentially runs the disassembler
 * backwards. The process is tenuous, but works well enough for interactive single-instruction
 * assembly. It is not nearly as fast as disassembly, since after all, SLEIGH was not designed for
 * assembly. The assembler is great for interactive patching and for building small samples in unit
 * tests. For other cases, a real tool chain is likely more appropriate.
 * 
 * <h2>A Review of Disassembly</h2>
 * 
 * <p>
 * Before diving into assembly, it may be helpful to review SLEIGH and disassembly, at least as far
 * as I understand. SLEIGH is really a specification of three distinct things, all related by trees
 * of "constructors." 1) A mnemonic grammar, 2) A machine-code grammar, 3) Run-time semantics, i.e.,
 * p-code. The third is consumed primarily by the decompiler, the emulator, and other analysis, and
 * is of little concern to the (dis)assembler. All three are tightly bound. A single constructor
 * specifies a production in both grammars, constraints for selecting the production, as well as the
 * generated run-time semantics. Consider an example:
 * 
 * <pre>
 * :ADD regD,imm8 is op=5 & regD & imm8 { regD = regD + imm8; }
 * </pre>
 * 
 * <p>
 * The colon indicates this constructor applies to the root "instruction" table. The mnemonic
 * production precedes the <code>is</code> keyword. The machine-code constraints and production
 * follow. Finally, the semantics appear within braces.
 * 
 * <p>
 * To support bitfield parsing, a list of token formats and fields within must be declared. The
 * machine-code production may specify constraints in terms of those fields. Such constraints become
 * patterns that the parser uses to choose a constructor. For example, we may have
 * <code>op=(0,3);regD=(4,7);imm8=(8,15)</code>. In little endian, this would indicate a 2-byte
 * token:
 * 
 * <pre>
 *  +-4----+-4----+-8----------+
 *  | regD |  op  |    imm8    |
 *  +------+------+------------+
 * </pre>
 * 
 * <p>
 * Thus, this constructor is assigned the pattern <code>0101....</code>, which handles
 * <code>op=5</code>. <code>regD</code> and <code>imm8</code> remain as operands. The operands of
 * the machine-code production refer to fields and subtables. During disassembly, those operands are
 * parsed in the order named: left to right, depth first. For the (root) instruction table and each
 * subtable, the disassembler selects exactly one constructor. The parser may only examine one
 * machine-code token at a time; however, the token can be large (32 bits is common), and it may
 * make several sub-table decisions based on fields within a single token, essentially allowing it
 * to look ahead and parse those fields out of order. In the example, the parser will technically
 * examine the <code>op</code> field before parsing <code>regD</code>.
 * 
 * <p>
 * When parsing a table or subtable, if no constructor's constraints can be matched, parsing fails.
 * Each token is some number of bytes in size. The parser advances to the next token when it
 * encounters a semicolon in the machine-code production. Note that when the parser returns to a
 * parent constructor, i.e., the PDA pops its stack, the parser may return to a previous token. If
 * that behavior is not desired, a machine-code production may contain ellipses, causing the parser
 * to advance to the next token, even considering those tokens already examined by operands to the
 * ellipses' left. Once all operands of the selected instruction constructor have been parsed, the
 * resulting constructor tree ("prototype") is recorded and returned.
 * 
 * <p>
 * To display the instruction's mnemonic, the prototype is walked, generating the tokens ("print
 * pieces") from the mnemonic production of each constructor. The walk is ordered according to that
 * mnemonic production. The mnemonic grammar consists of syntactic text and symbols. Any symbols it
 * uses must also appear in the machine-code production. Where the symbol is a sub-table, it behaves
 * like a non-terminal in the grammar: It generates the print pieces of the constructor selected for
 * the sub-table. Where the symbol is a field, it behaves like a terminal. It displays the numeric
 * value of the field, or in the case of attached names, e.g., register names, it displays the name.
 * 
 * <p>
 * To complicate matters, but greatly increase the capability of the disassembler, SLEIGH introduces
 * temporary symbols and context to the disassembler. A temporary symbol allows the computation of
 * displayed values from fields. (The value may also be used by the p-code generator.) For example,
 * a language may permit the expression of immediates as a value and a shift. Temporary symbols
 * permit the effective value to be computed and displayed. Thus, a temporary symbol is valid in the
 * mnemonic production. Context serves at least two purposes: 1) To propagate auxiliary information
 * to sub-tables during disassembly, and 2) To handle persistent state changes in a processor that
 * modify its decoder, e.g., ARM in THUMB mode. The latter is accomplished by marking regions of
 * memory with this contextual information. Context is implemented by introducing a context
 * register. It behaves like a special mutable token, initialized from the disassembler's memory,
 * the context marked at the instruction's start address, or the language's default context. Like
 * token fields, context fields can be referred to by a constructor's machine-code production,
 * either to form constraints or to parse as operands. Fields may be modified by including mutations
 * in the constructor. Mutations and temporary symbols are defined by assigning an expression to the
 * field or symbol. Those expressions may refer to other fields and temporary symbols in the scope
 * of that constructor. Since mutations are meant to be propagated down, they must be applied in
 * pre-order during parsing. Note that context is not saved on any sort of stack, thus it is
 * possible for context mutations in a sub-table operand (and its sub-table operands) to affect
 * parsing of sibling sub-table operands to the right.
 * 
 * <p>
 * When disassembling entire subroutines, the disassembler must propagate context changes from
 * instruction to instruction. Some bits of the context register are marked "global." Those bits,
 * when instruction parsing succeeds, are taken as the "output context" of the resulting
 * instruction. Propagation follows from a recursive traversal disassembly strategy, i.e., it heeds
 * the branch targets of the instruction. The generated p-code is used to determine whether the
 * instruction has branches and/or fall-through. If the output context differs from the default
 * context, the disassembler saves it as the initial context for the next instruction. If the
 * instruction has a branch target, the output context is marked at the target address.
 * 
 * <h2>Assembly</h2>
 * 
 * <p>
 * Conceptually, assembly is a straightforward reversal of the disassembly process; however, the
 * actual implementation is far more complex. To assemble an instruction there are three distinct
 * phases: 1) Parsing, 2) Prototype generation, 3) Machine code generation. Each phase may take
 * advantage of pre-computed artifacts.
 * 
 * <h3>Parsing Assembly Mnemonics</h3>
 * 
 * <p>
 * To parse, we pre-compute a LALR(1) parser based on mnemonic grammar. Because different
 * constructors may specify the same mnemonic production as others in the same table, we have to
 * associate all such constructors to the production. This step takes some time, and may be better
 * suited as a build-time step. Because SLEIGH specifications are not generally concerned with
 * eliminating ambiguity of printed instructions (rather, it only does so for instruction bytes), we
 * must consider that the grammar could be ambiguous. To handle this, the action/goto table is
 * permitted multiple entries per cell, and we allow backtracking. There are also cases where tokens
 * are not actually separated by spaces. For example, in the {@code ia.sinc} file, there is JMP, and
 * J^cc, meaning, the lexer must consider J as a token as well as JMP, introducing another source of
 * possible backtracking. Despite that, parsing an instruction is fairly quick, since the sentences
 * are rather short. The pre-compute part of this process is implemented in {@link #buildGrammar()}
 * and {@link #buildParser()}. Parsing is then encapsulated in {@link AssemblyParser}.
 * 
 * <h3>Prototype Generation</h3>
 * 
 * <p>
 * To generate prototypes, we examine each resulting parse tree. If there are no parse trees, then a
 * syntax errors is reported. Otherwise, for each tree, starting at the root production, we consider
 * all associated constructors, matching each print piece to its corresponding operand on the
 * machine-code side. For sub-table operands, the production substituted for the associated
 * non-terminal guides generation, recursively. For other operands, the associated terminal provides
 * the value or name. To mimic the token advancement of the disassembler, a shift is computed and
 * stored for each operand. Computing the shift requires computing each operand's length, and so
 * once the root of each prototype is generated, the instruction length is also known. Patterns and
 * mutations are applied to mimic the disassembly process: pre-ordered, depth first, left to right,
 * heeding the computed shift. If a pattern or mutation for a constructor conflicts with what's been
 * generated so far, the constructor is pruned. If all possible constructors for a sub-table operand
 * are pruned, then the containing constructor is also pruned.
 * 
 * <p>
 * In some cases, an operand appears in the machine-code production, but not the mnemonic
 * production: so-called "hidden operands." These pose a potential issue for the assembler, because
 * nothing syntactic can guide prototype generation. For hidden sub-table operands, we must consider
 * all constructors in the table. Furthermore, all operands of those constructors are considered
 * "hidden," and so we exhaust recursively. For other hidden operands, the value is left
 * unspecified. The prototype generation process is encapsulated in
 * {@link AssemblyConstructStateGenerator}.
 * 
 * <h3>Machine Code Generation</h3>
 * 
 * <p>
 * Machine code generation is a complex process, but it follows a straightforward reversal of the
 * disassembler's parse phase. For each prototype, we start at the leaves (non-sub-table operands)
 * and proceed upwards. This is still a depth-first traversal, but unlike disassembly, generation
 * proceeds in post-order and right to left, as follows. Starting at the root:
 * 
 * <ol>
 * <li>Resolve operands from right to left, descending into sub-table operands.</li>
 * <li>Solve context mutations, in reverse order.
 * <li>Apply the required patterns
 * </ol>
 * 
 * <p>
 * Note that for a single prototype, a constructor has already been selected for each sub-table
 * operand. The resolution of sub-table operands follows the same process as for the root
 * constructor.
 * 
 * <p>
 * For other operands, resolution proceeds by solving the operand's defining expression set equal to
 * the value specified by the terminal. The resulting values are written into their respective token
 * or context fields, generating an "assembly pattern." An assembly pattern is simply a masked bit
 * sequence recording what is expected in the instruction buffer and context register. Each bit is
 * 0, 1, or unspecified. In many cases, the "defining expression" is simply a field, so "solving"
 * degenerates simply to "writing" the specified value into the field. Solving expressions is only
 * required when a terminal defines the value of a temporary symbol. If the value is unspecified,
 * i.e., it is a hidden operand, then no fields are written. Thus, hidden non-sub-table operands
 * generate empty patterns.
 * 
 * <p>
 * As machine code generation proceeds right to left in a constructor, the resulting assembly
 * patterns are accumulated. If a generated pattern conflicts with that accumulated so far, the
 * pattern is pruned, likely halting generation of the current prototype. Once all operands have
 * been successfully resolved, the constructor's context mutations are solved. These tend to get
 * complicated since some fields may have values defined by the accumulated pattern, and some may
 * not. The changes are processed in reverse order from specified in the constructor, since fields
 * may be mutated in a way that forms data dependences among them. To solve, the field on the
 * left-hand side of the mutation is read, then it is set equal to the right-hand size and passed to
 * the solver. Because, from the disassembly perspective, the left-hand side is about to be written,
 * its value is cleared before passed to the solver. If successful, the solver returns patterns that
 * satisfy the equation. Resolution accumulates the patterns. If solving fails, or the patterns
 * conflict, it is pruned. Finally, the patterns required to select the constructor are applied,
 * again pruning conflicts. Note that a constructor may specify multiple patterns, e.g., if a
 * constraint is <code>op == 5 || op == 6</code>. Thus, overall, it is possible a single prototype
 * will generate multiple assembly patterns. This process is encapsulated in
 * {@link AssemblyConstructState}.
 * 
 * <h3>Handling Context and Prefixes</h3>
 * 
 * <p>
 * Once the root constructor has been completely resolved, the resulting instruction patterns
 * comprise the generated instruction bytes. However, we must consider the context pattern, too. In
 * practice, the assembler is invoked at a particular address, and the program database may provide
 * an initial context (as marked during previous disassembly). In other words, when patching an
 * instruction, we have to keep any persistent context in place. Thus, we can further cull patterns
 * whose context does not match. This intuition is frustrated by the possibility of constructors
 * with the mnemonic production <code>^instruction</code>, though. These "pure recursive"
 * constructors are often (ab)used to handle instruction prefixes, e.g.:
 * 
 * <code>
 * :^instruction is prefixed=0 & byte=0xff; instruction [ prefixed=1; ] {}
 * </code>
 * 
 * <p>
 * There are no syntactic elements that would cue the assembly parser to use this constructor.
 * Instead, we rely on the context register. Were it not for these kinds of constructors, we could
 * use the saved context as input to the prototype generation phase; however, we cannot. Instead, we
 * use the empty context and delay this step until after machine code generation. During assembler
 * construction, we pre-compute a "context transition graph." The mnemonic production
 * <code>[instruction] => [instruction]</code> has associated with it all pure recursive
 * constructors. Naturally, that production cannot be included in the parser, as it would generate
 * increasingly deep parse trees <em>ad infinitum</em>. The graph starts with a seed node: the
 * language's default context. Then each pure recursive constructor is considered as an edge,
 * leading to the node resulting from applying that constructor, mimicking disassembly. This
 * proceeds for each unvisited node until no new nodes are produced. This component is encapsulated
 * in {@link AssemblyContextGraph}.
 * 
 * <p>
 * To generate prefixes, we seek the shortest paths from nodes whose context pattern match the
 * initial context to nodes whose context pattern matches the generated assembly pattern. Note that
 * the shortest path may be the zero-length path. If no paths are found, assembly fails. Machine
 * code generation then proceeds by considering each path, and resolving the constructors in
 * reverse, in the same manner as constructors from the prototype are resolved. Note that the
 * patterns may need to be shifted to accommodate prefix tokens. This is accomplished by examining
 * the shift of the nested instruction operand for each constructor. This process is implemented in
 * {@link AssemblyTreeResolver#resolveRootRecursion(AssemblyResolutionResults)}.
 * 
 * <h3>Final Steps</h3>
 * 
 * <p>
 * As a final fail safe, the generated instructions are fed back through the disassembler and the
 * resulting constructor trees are compared. If not equivalent, the instruction is dropped. It is
 * possible (common in fact) that the generated assembly instruction pattern is not fully defined.
 * By default, the assembler will substitute 0 for each undefined bit. However, the assembler API
 * allows the retrieval of the generated pattern, since a user may wish to substitute other values.
 * 
 * <p>
 * If, in the end, no instructions are generated, a semantic error is reported. Often, the
 * description is unwieldy, since it comprises a list of reasons each pattern was pruned. From the
 * user side, it is usually sufficient to say, "sorry." From the language developer side, it may be
 * useful to manually reconstruct the prototype and discover the conflicts. To that end, the
 * implementation includes optional diagnostics, but even then, decoding them takes some familiarity
 * and expertise.
 */
public class SleighAssemblerBuilder implements AssemblerBuilder {
	protected static final DbgTimer dbg =
		SystemUtilities.isInTestingBatchMode() ? DbgTimer.INACTIVE : DbgTimer.ACTIVE;

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
							rhs.addSymbol(sym);
						}
						else {
							rhs.addSeparators(str);
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
