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
package ghidra.program.model.lang;

import java.io.*;
import java.util.*;
import java.util.stream.Collectors;

import org.antlr.runtime.*;
import org.antlr.runtime.tree.CommonTreeNodeStream;

import generic.stl.VectorSTL;
import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.symbol.Symbol;
import ghidra.app.plugin.processors.sleigh.symbol.SymbolTable;
import ghidra.app.plugin.processors.sleigh.symbol.UseropSymbol;
import ghidra.app.plugin.processors.sleigh.symbol.VarnodeSymbol;
import ghidra.app.plugin.processors.sleigh.template.*;
import ghidra.pcode.utils.MessageFormattingUtils;
import ghidra.pcodeCPort.address.Address;
import ghidra.pcodeCPort.context.SleighError;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.slgh_compile.*;
import ghidra.pcodeCPort.slghsymbol.*;
import ghidra.pcodeCPort.slghsymbol.EndSymbol;
import ghidra.pcodeCPort.slghsymbol.OperandSymbol;
import ghidra.pcodeCPort.slghsymbol.StartSymbol;
import ghidra.pcodeCPort.space.*;
import ghidra.pcodeCPort.xml.DocumentStorage;
import ghidra.program.model.address.*;
import ghidra.sleigh.grammar.*;
import ghidra.sleigh.grammar.SleighParser_SemanticParser.semantic_return;
import ghidra.util.exception.AssertException;

/**
 * This class is intended to parse p-code snippets, typically from compiler specification files or
 * extensions. This is outside the normal SLEIGH compilation process, and the parser is built on top
 * of an existing SleighLanguage.
 */
public class PcodeParser extends PcodeCompile {

	private SleighBase sleigh;
	private AddressFactory addrFactory;
	private long tempbase;
	private HashMap<String, SleighSymbol> symbolMap = new HashMap<>();

	//record symbols added so that they can be removed to reset the parser
	private HashSet<String> currentSymbols = new HashSet<>();

	protected PcodeParser(SleighBase sleigh) {

		this.sleigh = sleigh;
		initializeSymbols();
	}

	/**
	 * Build parser from an existing SleighLanguage.
	 * 
	 * @param language is the existing language
	 * @param ubase is the starting offset for allocating temporary registers
	 */
	public PcodeParser(SleighLanguage language, long ubase) {

		addrFactory = language.getAddressFactory();
		sleigh = new PcodeTranslate(language, ubase);
		initializeSymbols();
	}

	private void initializeSymbols() {
		tempbase = sleigh.getUniqueBase();

		Location internalLoc = Location.INTERNALLY_DEFINED;
		symbolMap.put("inst_start", new StartSymbol(internalLoc, "inst_start", getConstantSpace()));
		symbolMap.put("inst_next", new EndSymbol(internalLoc, "inst_next", getConstantSpace()));
		symbolMap.put("inst_next2", new Next2Symbol(internalLoc, "inst_next2", getConstantSpace()));
		symbolMap.put("inst_ref", new FlowRefSymbol(internalLoc, "inst_ref", getConstantSpace()));
		symbolMap.put("inst_dest",
			new FlowDestSymbol(internalLoc, "inst_dest", getConstantSpace()));
	}

	/**
	 * Inject a symbol representing an "operand" to the pcode snippet.
	 * 
	 * <p>
	 * This puts a placeholder in the resulting template, which gets filled in with the context
	 * specific storage locations when final p-code is generated
	 * 
	 * @param loc is location information for the operand
	 * @param name of operand symbol
	 * @param index to use for the placeholder
	 */
	public void addOperand(Location loc, String name, int index) {
		OperandSymbol sym = new OperandSymbol(loc, name, index, null);
		addSymbol(sym);
	}

	@Override
	public void addSymbol(SleighSymbol sym) {
		SleighSymbol s = sleigh.findSymbol(sym.getName());
		if (s == null) {
			s = symbolMap.get(sym.getName());
		}
		if (s != null) {
			if (s != sym) {
				throw new SleighError("Duplicate symbol name: " + sym.getName() +
					" (previously defined at " + s.location + ")", sym.getLocation());
			}
		}
		else {
			symbolMap.put(sym.getName(), sym);
			currentSymbols.add(sym.getName());
		}
	}

	public void clearSymbols() {
		for (String symbol : currentSymbols) {
			symbolMap.remove(symbol);
		}
		currentSymbols.clear();
	}

	public long getNextTempOffset() {
		return tempbase;
	}

	@Override
	public long allocateTemp() {
		long base = tempbase;
		tempbase = base + SleighBase.MAX_UNIQUE_SIZE;
		return base;
	}

	@Override
	public VectorSTL<ghidra.pcodeCPort.semantics.OpTpl> createMacroUse(Location location,
			MacroSymbol sym, VectorSTL<ExprTree> param) {
		throw new SleighError("Pcode snippet parsing does not support use of macros", location);
	}

	@Override
	public SleighSymbol findSymbol(String nm) {
		SleighSymbol sym = symbolMap.get(nm);
		if (sym != null) {
			return sym;
		}
		return sleigh.findSymbol(nm);
	}

	public SleighBase getSleigh() {
		return sleigh;
	}

	@Override
	public AddrSpace getConstantSpace() {
		return sleigh.getConstantSpace();
	}

	@Override
	public AddrSpace getDefaultSpace() {
		return sleigh.getDefaultSpace();
	}

	@Override
	public AddrSpace getUniqueSpace() {
		return sleigh.getUniqueSpace();
	}

	@Override
	public void recordNop(Location location) {
		// No NOP statistics collected for snippet parsing
	}

	// Make sure label symbols are used properly
	private String checkLabels() {
		List<String> errors = new ArrayList<>();
		for (SleighSymbol sym : symbolMap.values()) {
			if (sym.getType() != symbol_type.label_symbol) {
				continue;
			}
			LabelSymbol labsym = (LabelSymbol) sym;
			if (labsym.getRefCount() == 0) {
				errors.add(MessageFormattingUtils.format(labsym.location,
					String.format("Label <%s> was placed but never used", sym.getName())));

			}
			else if (!labsym.isPlaced()) {
				errors.add(MessageFormattingUtils.format(labsym.location,
					String.format("Label <%s> was referenced but never placed", sym.getName())));
			}
		}
		return errors.stream().collect(Collectors.joining("  "));

	}

	private ConstructTpl buildConstructor(ghidra.pcodeCPort.semantics.ConstructTpl rtl) {
		String errstring = "";
		if (rtl != null) {
			errstring = checkLabels();
			if ((errstring.length() == 0) && (!propagateSize(rtl))) {
				errstring = "   Could not resolve at least 1 variable size";
			}
			if ((errstring.length() == 0) && rtl.delaySlot() != 0) { // Delay slot is present in this
				errstring = "   delayslot not permitted in pcode fragment";
			}
			if (rtl.getResult() != null) {
				errstring = "   export not permitted in pcode fragment";
			}
		}
		if (errstring.length() != 0) {
			throw new SleighException(errstring);
		}
		return translateConstructTpl(rtl);
	}

	/**
	 * This class wraps on existing SleighLanguage with the SleighBase interface expected by
	 * PcodeCompile. It populates the symbol table with user-defined operations and the global
	 * VarnodeSymbol objects, which typically includes all the general purpose registers.
	 */
	public static class PcodeTranslate extends SleighBase {

		private void copySpaces(SleighLanguage language) {
			insertSpace(new ConstantSpace(this));
			insertSpace(
				new OtherSpace(this, SpaceNames.OTHER_SPACE_NAME, SpaceNames.OTHER_SPACE_INDEX));
			AddressSpace[] spaces = language.getAddressFactory().getAllAddressSpaces();
			for (AddressSpace spc : spaces) {
				if (spc.getUnique() < 2) {
					continue;
				}
				AddrSpace resSpace;
				int sz = spc.getSize();
				if (spc instanceof SegmentedAddressSpace) {
					// TODO: SegmentedAddressSpace shouldn't really return 21
					sz = 32;
				}
				if (sz > 64) {
					sz = 64;
				}
				int bytesize = (sz + 7) / 8; // Convert bits to bytes
				switch (spc.getType()) {
					case AddressSpace.TYPE_UNIQUE:
						resSpace = new UniqueSpace(this, spc.getUnique(), 0);
						break;
					case AddressSpace.TYPE_OTHER:
						resSpace = new OtherSpace(this, spc.getName(), spc.getUnique());
						break;
					case AddressSpace.TYPE_RAM:
						resSpace = new AddrSpace(this, spacetype.IPTR_PROCESSOR, spc.getName(),
							bytesize, spc.getAddressableUnitSize(), spc.getUnique(),
							AddrSpace.hasphysical, 1);
						break;
					case AddressSpace.TYPE_REGISTER:
						resSpace = new AddrSpace(this, spacetype.IPTR_PROCESSOR, spc.getName(),
							bytesize, spc.getAddressableUnitSize(), spc.getUnique(),
							AddrSpace.hasphysical, 0);
						break;
					default:
						resSpace = null;
				}
				if (resSpace == null) {
					break;
				}
				insertSpace(resSpace);
			}
			setDefaultSpace(language.getDefaultSpace().getUnique());
		}

		/**
		 * Populate the predefined symbol table for the parser from the given SLEIGH language. We
		 * only use user-defined op symbols and varnode symbols.
		 * 
		 * @param language is the SLEIGH language
		 */
		private void copySymbols(SleighLanguage language) {
			SymbolTable langTable = language.getSymbolTable();
			symtab.addScope();		// Global scope
			for (Symbol sym : langTable.getSymbolList()) {
				if (sym instanceof UseropSymbol) {
					UserOpSymbol cloneSym = new UserOpSymbol(null, sym.getName());
					cloneSym.setIndex(((UseropSymbol) sym).getIndex());
					symtab.addSymbol(cloneSym);
				}
				else if (sym instanceof VarnodeSymbol) {
					VarnodeData vData = ((VarnodeSymbol) sym).getFixedVarnode();
					if ("contextreg".equals(sym.getName())) {
						continue;
					}
					ghidra.pcodeCPort.slghsymbol.VarnodeSymbol cloneSym;
					AddrSpace base = getSpace(vData.space.getUnique());
					cloneSym = new ghidra.pcodeCPort.slghsymbol.VarnodeSymbol(null, sym.getName(),
						base, vData.offset, vData.size);
					symtab.addSymbol(cloneSym);
				}
			}
		}

		public PcodeTranslate(SleighLanguage language, long ubase) {
			super();
			target_endian = language.isBigEndian() ? 1 : 0;
			alignment = 0;
			setUniqueBase(ubase);

			copySpaces(language);
			copySymbols(language);

			for (int i = 0; i < numSpaces(); i++) {
				AddrSpace space = getSpace(i);
				symtab.addSymbol(new SpaceSymbol(null, space));
			}
		}

		@Override
		public void initialize(DocumentStorage store) {
			// Unused
		}

		@Override
		public int printAssembly(PrintStream s, int size, Address baseaddr) {
			return 0;
		}

		@Override
		public int instructionLength(Address baseaddr) {
			return 0;
		}
	}

	public ConstructTpl translateConstructTpl(
			ghidra.pcodeCPort.semantics.ConstructTpl constructTpl) {
		HandleTpl handle = null;
		if (constructTpl.getResult() != null) {
			handle = translateHandleTpl(constructTpl.getResult());
		}
		OpTpl[] vec = new OpTpl[constructTpl.getOpvec().size()];
		for (int i = 0; i < vec.length; ++i) {
			vec[i] = translateOpTpl(constructTpl.getOpvec().get(i));
		}
		return new ConstructTpl(vec, handle, constructTpl.numLabels());
	}

	public HandleTpl translateHandleTpl(ghidra.pcodeCPort.semantics.HandleTpl handleTpl) {
		return new HandleTpl(translateConstTpl(handleTpl.getSpace()),
			translateConstTpl(handleTpl.getSize()), translateConstTpl(handleTpl.getPtrSpace()),
			translateConstTpl(handleTpl.getPtrOffset()), translateConstTpl(handleTpl.getPtrSize()),
			translateConstTpl(handleTpl.getTempSpace()),
			translateConstTpl(handleTpl.getTempOffset()));
	}

	public OpTpl translateOpTpl(ghidra.pcodeCPort.semantics.OpTpl opTpl) {
		VarnodeTpl output = null;
		if (opTpl.getOut() != null) {
			output = translateVarnodeTpl(opTpl.getOut());
		}
		VarnodeTpl[] input = new VarnodeTpl[opTpl.numInput()];
		for (int i = 0; i < input.length; ++i) {
			input[i] = translateVarnodeTpl(opTpl.getIn(i));
		}
		return new OpTpl(opTpl.getOpcode().ordinal(), output, input);
	}

	public VarnodeTpl translateVarnodeTpl(ghidra.pcodeCPort.semantics.VarnodeTpl varnodeTpl) {
		return new VarnodeTpl(translateConstTpl(varnodeTpl.getSpace()),
			translateConstTpl(varnodeTpl.getOffset()), translateConstTpl(varnodeTpl.getSize()));
	}

	public ConstTpl translateConstTpl(ghidra.pcodeCPort.semantics.ConstTpl constTpl) {
		AddrSpace spc = constTpl.getSpace();
		AddressSpace resSpace = null;
		if (spc != null) {
			resSpace = addrFactory.getAddressSpace(spc.getName());
		}
		int select = 0;
		ghidra.pcodeCPort.semantics.ConstTpl.v_field field = constTpl.getSelect();
		if (field != null) {
			select = field.ordinal();
		}
		return new ConstTpl(constTpl.getType().ordinal(), constTpl.getReal(), resSpace,
			constTpl.getHandleIndex(), select);
	}

	/**
	 * Compile pcode semantic statements.
	 * 
	 * @param pcodeStatements is the raw source to parse
	 * @param srcFile source filename from which pcodeStatements came (
	 * @param srcLine line number in srcFile corresponding to pcodeStatements
	 * @return ConstructTpl. A null may be returned or an exception thrown if parsing/compiling
	 *         fails (see application log for errors).
	 * @throws SleighException pcode compile error
	 */
	public ConstructTpl compilePcode(String pcodeStatements, String srcFile, int srcLine)
			throws SleighException {

		LineArrayListWriter writer = null;
		try {
			writer = new LineArrayListWriter();
			ParsingEnvironment env = new ParsingEnvironment(writer);

			// inject pcode statement lines into writer (needed for error reporting)
			BufferedReader r = new BufferedReader(new StringReader(pcodeStatements));
			String line;
			while ((line = r.readLine()) != null) {
				writer.write(line);
				writer.newLine();
			}

			CharStream input = new ANTLRStringStream(writer.toString());

			env.getLocator().registerLocation(input.getLine(), new Location(srcFile, srcLine));

			SleighLexer lex = new SleighLexer(input);
			lex.setEnv(env);
			UnbufferedTokenStream tokens = new UnbufferedTokenStream(lex);
			SleighParser parser = new SleighParser(tokens);
			parser.setEnv(env);
			parser.setLexer(lex);
			lex.pushMode(SleighRecognizerConstants.SEMANTIC);
			semantic_return semantic = parser.semantic();
			lex.popMode();

			CommonTreeNodeStream nodes = new CommonTreeNodeStream(semantic.getTree());
			nodes.setTokenStream(tokens);
			// ANTLRUtil.debugNodeStream(nodes, System.out);
			SleighCompiler walker = new SleighCompiler(nodes);

			SectionVector rtl = walker.semantic(env, null, this, semantic.getTree(), false, false);

			if (getErrors() != 0) {
				return null;
			}

			ConstructTpl result = null;
			if (rtl != null) {
				result = buildConstructor(rtl.getMainSection());
			}

			return result;
		}
		catch (IOException e) {
			throw new AssertException(); // unexpected condition
		}
		catch (RecognitionException e) {
			throw new SleighException("Semantic compilation error: " + e.getMessage(), e);
		}
		catch (BailoutException e) {
			throw new SleighException("Unrecoverable error(s), halting compilation", e);
		}
		catch (NullPointerException e) {
			throw new SleighException("Unrecoverable error(s), halting compilation", e);
		}
		finally {
			if (writer != null) {
				try {
					writer.close();
				}
				catch (IOException e) {
					// squash!!! we tried
				}
			}
		}
	}

	@Override
	public SectionSymbol newSectionSymbol(Location where, String text) {
		throw new SleighError("Pcode snippet parsing does not support use of sections", where);
	}

	@Override
	public VectorSTL<ghidra.pcodeCPort.semantics.OpTpl> createCrossBuild(Location where,
			ghidra.pcodeCPort.semantics.VarnodeTpl v, SectionSymbol second) {
		throw new SleighError("Pcode snippet parsing does not support use of sections", where);
	}

	@Override
	public SectionVector standaloneSection(ghidra.pcodeCPort.semantics.ConstructTpl main) {
		// Create SectionVector for just the main rtl section with no named sections
		SectionVector res = new SectionVector(main, null);
		return res;
	}

	@Override
	public SectionVector firstNamedSection(ghidra.pcodeCPort.semantics.ConstructTpl main,
			SectionSymbol sym) {
		throw new SleighError("Pcode snippet parsing does not support use of sections",
			sym.location);
	}

	@Override
	public SectionVector nextNamedSection(SectionVector vec,
			ghidra.pcodeCPort.semantics.ConstructTpl section, SectionSymbol sym) {
		throw new SleighError("Pcode snippet parsing does not support use of sections",
			sym.location);
	}

	@Override
	public SectionVector finalNamedSection(SectionVector vec,
			ghidra.pcodeCPort.semantics.ConstructTpl section) {
		throw new SleighError("Pcode snippet parsing does not support use of sections", null); // can never get here
	}
}
