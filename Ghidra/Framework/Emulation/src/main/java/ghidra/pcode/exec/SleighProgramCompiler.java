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
package ghidra.pcode.exec;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.pcode.utils.MessageFormattingUtils;
import ghidra.pcodeCPort.pcoderaw.VarnodeData;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.slghsymbol.*;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.sleigh.grammar.Location;
import ghidra.util.Msg;

/**
 * Methods for compiling p-code programs for various purposes
 * 
 * <p>
 * Depending on the purpose, special provisions may be necessary around the execution of the
 * resulting program. Many utility methods are declared public here because they, well, they have
 * utility. The main public methods of this class, however, all start with {@code compile}....
 */
public enum SleighProgramCompiler {
	;
	private static final String EXPRESSION_SOURCE_NAME = "expression";
	public static final String NIL_SYMBOL_NAME = "__nil";

	public interface PcodeLogEntry {
		public static String formatList(List<PcodeLogEntry> list) {
			return list.stream().map(e -> e.format()).collect(Collectors.joining("\n"));
		}

		Location loc();

		String msg();

		String type();

		default String format() {
			return "%s: %s".formatted(type(), MessageFormattingUtils.format(loc(), msg()));
		}
	}

	record PcodeError(Location loc, String msg) implements PcodeLogEntry {
		@Override
		public String type() {
			return "ERROR";
		}
	}

	record PcodeWarning(Location loc, String msg) implements PcodeLogEntry {
		@Override
		public String type() {
			return "WARNING";
		}
	}

	public static class DetailedSleighException extends SleighException {
		private final List<PcodeLogEntry> details;

		public DetailedSleighException(List<PcodeLogEntry> details) {
			super(PcodeLogEntry.formatList(details));
			this.details = List.copyOf(details);
		}

		public List<PcodeLogEntry> getDetails() {
			return details;
		}
	}

	/**
	 * A p-code parser that provides programmatic access to error diagnostics.
	 */
	public static class ErrorCollectingPcodeParser extends PcodeParser {
		private final List<PcodeLogEntry> entries = new ArrayList<>();

		public ErrorCollectingPcodeParser(SleighLanguage language) {
			super(language, UniqueLayout.INJECT.getOffset(language));
		}

		@Override
		public void reportError(Location location, String msg) {
			entries.add(new PcodeError(location, msg));
			super.reportError(location, msg);
		}

		@Override
		public void reportWarning(Location location, String msg) {
			entries.add(new PcodeWarning(location, msg));
			super.reportWarning(location, msg);
		}

		@Override
		public ConstructTpl compilePcode(String pcodeStatements, String srcFile, int srcLine)
				throws SleighException {
			try {
				return super.compilePcode(pcodeStatements, srcFile, srcLine);
			}
			finally {
				if (getErrors() != 0) {
					throw new DetailedSleighException(entries);
				}
			}
		}
	}

	/**
	 * Create a p-code parser for the given language
	 * 
	 * @param language the language
	 * @return a parser
	 */
	public static PcodeParser createParser(SleighLanguage language) {
		return new ErrorCollectingPcodeParser(language);
	}

	/**
	 * Compile the given source into a p-code template
	 * 
	 * @see #compileProgram(SleighLanguage, String, List, PcodeUseropLibrary)
	 * @param language the language
	 * @param parser the parser
	 * @param sourceName the name of the program, for error diagnostics
	 * @param source the Sleigh source
	 * @return the constructor template
	 */
	public static ConstructTpl compileTemplate(Language language, PcodeParser parser,
			String sourceName, String source) {
		return parser.compilePcode(source, sourceName, 1);
	}

	/**
	 * Construct a list of p-code ops from the given template
	 * 
	 * @param language the language generating the template and p-code
	 * @param template the template
	 * @return the list of p-code ops
	 * @throws UnknownInstructionException in case of crossbuilds, the target instruction is unknown
	 * @throws MemoryAccessException in case of crossbuilds, the target address cannot be accessed
	 * @throws IOException for errors in during emitting
	 */
	public static List<PcodeOp> buildOps(Language language, ConstructTpl template)
			throws UnknownInstructionException, MemoryAccessException, IOException {
		Address zero = language.getDefaultSpace().getAddress(0);
		SleighParserContext c = new SleighParserContext(zero, zero, zero, zero);
		ParserWalker walk = new ParserWalker(c);
		PcodeEmitObjects emit = new PcodeEmitObjects(walk);

		emit.build(template, 0);
		emit.resolveRelatives();
		return List.of(emit.getPcodeOp());
	}

	/**
	 * Add extra user-op symbols to the parser's table
	 * 
	 * <p>
	 * The map cannot contain symbols whose user-op indices are already defined by the language.
	 * 
	 * @param parser the parser to modify
	 * @param symbols the map of extra symbols
	 */
	protected static void addParserSymbols(PcodeParser parser, Map<Integer, UserOpSymbol> symbols) {
		for (UserOpSymbol sym : symbols.values()) {
			parser.addSymbol(sym);
		}
	}

	/**
	 * Add a symbol for unwanted result
	 * 
	 * <p>
	 * This is basically a hack to avoid NPEs when no output varnode is given.
	 * 
	 * @param parser the parser to add the symbol to
	 * @return the nil symbol
	 */
	protected static VarnodeSymbol addNilSymbol(PcodeParser parser) {
		SleighSymbol exists = parser.findSymbol(NIL_SYMBOL_NAME);
		if (exists != null) {
			// A ClassCastException here indicates a name collision
			return (VarnodeSymbol) exists;
		}
		long offset = parser.allocateTemp();
		VarnodeSymbol nil = new VarnodeSymbol(new Location("<util>", 0), NIL_SYMBOL_NAME,
			parser.getUniqueSpace(), offset, 1);
		parser.addSymbol(nil);
		return nil;
	}

	/**
	 * A factory for {@code PcodeProgram}s
	 *
	 * @param <T> the type of program to build
	 */
	public interface PcodeProgramConstructor<T extends PcodeProgram> {
		T construct(SleighLanguage language, List<PcodeOp> ops, Map<Integer, UserOpSymbol> symbols);
	}

	/**
	 * Invoke the given constructor with the given template and library symbols
	 * 
	 * @param <T> the type of the p-code program
	 * @param ctor the constructor, often a method reference to {@code ::new}
	 * @param language the language producing the p-code
	 * @param template the p-code constructor template
	 * @param libSyms the map of symbols by userop ID
	 * @return the p-code program
	 */
	public static <T extends PcodeProgram> T constructProgram(PcodeProgramConstructor<T> ctor,
			SleighLanguage language, ConstructTpl template, Map<Integer, UserOpSymbol> libSyms) {
		try {
			return ctor.construct(language, SleighProgramCompiler.buildOps(language, template),
				libSyms);
		}
		catch (UnknownInstructionException | MemoryAccessException | IOException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Compile the given Sleigh source into a simple p-code program with the given parser
	 * 
	 * <p>
	 * This is suitable for modifying program state using Sleigh statements. Most likely, in
	 * scripting, or perhaps in a Sleigh repl. The library given during compilation must match the
	 * library given for execution, at least in its binding of userop IDs to symbols.
	 * 
	 * @param the parser to use
	 * @param language the language of the target p-code machine
	 * @param sourceName a diagnostic name for the Sleigh source
	 * @param source the Sleigh source
	 * @param library the userop library or stub library for binding userop symbols
	 * @return the compiled p-code program
	 */
	public static PcodeProgram compileProgram(PcodeParser parser, SleighLanguage language,
			String sourceName, String source, PcodeUseropLibrary<?> library) {
		Map<Integer, UserOpSymbol> symbols = library.getSymbols(language);
		addParserSymbols(parser, symbols);

		ConstructTpl template = compileTemplate(language, parser, sourceName, source);
		return constructProgram(PcodeProgram::new, language, template, symbols);
	}

	/**
	 * Compile the given Sleigh source into a simple p-code program
	 * 
	 * @see #compileProgram(PcodeParser, SleighLanguage, String, String, PcodeUseropLibrary)
	 */
	public static PcodeProgram compileProgram(SleighLanguage language, String sourceName,
			String source, PcodeUseropLibrary<?> library) {
		return compileProgram(createParser(language), language, sourceName, source, library);
	}

	/**
	 * Compile the given Sleigh expression into a p-code program that can evaluate it, using the
	 * given parser
	 * 
	 * <p>
	 * TODO: Currently, expressions cannot be compiled for a user-supplied userop library. The
	 * evaluator p-code program uses its own library as a means of capturing the result; however,
	 * userop libraries are easily composed. It should be easy to add that feature if needed.
	 * 
	 * @param language the languge of the target p-code machine
	 * @param expression the Sleigh expression to be evaluated
	 * @return a p-code program whose {@link PcodeExpression#evaluate(PcodeExecutor)} method will
	 *         evaluate the expression on the given executor and its state.
	 */
	public static PcodeExpression compileExpression(PcodeParser parser, SleighLanguage language,
			String expression) {
		Map<Integer, UserOpSymbol> symbols = PcodeExpression.CAPTURING.getSymbols(language);
		addParserSymbols(parser, symbols);

		ConstructTpl template = compileTemplate(language, parser, EXPRESSION_SOURCE_NAME,
			PcodeExpression.RESULT_NAME + "(" + expression + ");");
		return constructProgram(PcodeExpression::new, language, template, symbols);
	}

	/**
	 * Compile the given Sleigh expression into a p-code program that can evaluate it
	 * 
	 * @see #compileExpression(PcodeParser, SleighLanguage, String)
	 */
	public static PcodeExpression compileExpression(SleighLanguage language, String expression) {
		return compileExpression(createParser(language), language, expression);
	}

	/**
	 * Generate a Sleigh symbol for context when compiling a userop definition
	 * 
	 * @param language the language of the target p-code machine
	 * @param sleigh a means of translating address spaces between execution and compilation
	 *            contexts
	 * @param opName a diagnostic name for the userop in which this parameter applies
	 * @param paramName the symbol name for the parameter
	 * @param arg the varnode to bind to the parameter symbol
	 * @return the named Sleigh symbol bound to the given varnode
	 */
	public static VarnodeSymbol paramSym(Language language, SleighBase sleigh, String opName,
			String paramName, Varnode arg) {
		AddressSpace gSpace = language.getAddressFactory().getAddressSpace(arg.getSpace());
		AddrSpace sSpace = sleigh.getSpace(gSpace.getUnique());
		return new VarnodeSymbol(new Location(opName, 0), paramName, sSpace, arg.getOffset(),
			arg.getSize());
	}

	/**
	 * Compile the definition of a p-code userop from Sleigh source into a p-code program
	 * 
	 * <p>
	 * TODO: Defining a userop from Sleigh source is currently a bit of a hack. It would be nice if
	 * there were a formalization of Sleigh/p-code subroutines. At the moment, the control flow for
	 * subroutines is handled out of band, which actually works fairly well. However, parameter
	 * passing and returning results is not well defined. The current solution is to alias the
	 * parameters to their arguments, implementing a pass-by-reference scheme. Similarly, the output
	 * variable is aliased to the symbol named {@link SleighPcodeUseropDefinition#OUT_SYMBOL_NAME},
	 * which could be problematic if no output variable is given. In this setup, the use of
	 * temporary variables is tenuous, since no provision is made to ensure a subroutine's
	 * allocation of temporary variables do not collide with those of callers lower in the stack.
	 * This could be partly resolved by creating a fresh unique space for each invocation, but then
	 * it becomes necessary to copy values from the caller's to the callee's. If we're strict about
	 * parameters being inputs, this is straightforward. If parameters can be used to communicate
	 * results, then we may need parameter attributes to indicate in, out, or inout. Of course,
	 * having a separate unique space per invocation implies the executor state can't simply have
	 * one unique space. Likely, the {@link PcodeFrame} would come to own its own unique space, but
	 * the {@link PcodeExecutorState} should probably still manufacture it.
	 * 
	 * @param language the language of the target p-code machine
	 * @param opName the name of the userop (used only for diagnostics here)
	 * @param params the names of parameters in order. Index 0 names the output symbol, probably
	 *            {@link SleighPcodeUseropDefinition#OUT_SYMBOL_NAME}
	 * @param source the Sleigh source
	 * @param library the userop library or stub library for binding userop symbols
	 * @param args the varnode arguments in order. Index 0 is the output varnode.
	 * @return a p-code program that implements the userop for the given arguments
	 */
	public static PcodeProgram compileUserop(SleighLanguage language, String opName,
			List<String> params, String source, PcodeUseropLibrary<?> library,
			List<Varnode> args) {
		PcodeParser parser = createParser(language);
		Map<Integer, UserOpSymbol> symbols = library.getSymbols(language);
		addParserSymbols(parser, symbols);
		SleighBase sleigh = parser.getSleigh();

		int count = params.size();
		if (args.size() != count) {
			throw new IllegalArgumentException("Mismatch of params and args sizes");
		}
		VarnodeSymbol nil = addNilSymbol(parser);
		VarnodeData nilVnData = nil.getFixedVarnode();
		for (int i = 0; i < count; i++) {
			String p = params.get(i);
			Varnode a = args.get(i);
			if (a == null && i == 0) { // Only allow output to be omitted
				parser.addSymbol(new VarnodeSymbol(nil.getLocation(), p, nilVnData.space,
					nilVnData.offset, nilVnData.size));
			}
			else {
				parser.addSymbol(paramSym(language, sleigh, opName, p, a));
			}
		}

		try {
			ConstructTpl template = compileTemplate(language, parser, opName, source);
			return constructProgram(PcodeProgram::new, language, template, symbols);
		}
		catch (Throwable t) {
			Msg.error(SleighProgramCompiler.class, "Error trying to compile userop:\n" + source);
			throw t;
		}
	}
}
