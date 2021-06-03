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
package ghidra.pcodeCPort.slgh_compile;

import java.io.*;
import java.util.*;
import java.util.stream.Collectors;

import org.antlr.runtime.*;
import org.antlr.runtime.tree.CommonTreeNodeStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdom.*;

import generic.stl.VectorSTL;
import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.utils.MessageFormattingUtils;
import ghidra.pcodeCPort.address.Address;
import ghidra.pcodeCPort.context.SleighError;
import ghidra.pcodeCPort.error.LowlevelError;
import ghidra.pcodeCPort.semantics.*;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.slghsymbol.*;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.pcodeCPort.utils.XmlUtils;
import ghidra.pcodeCPort.xml.DocumentStorage;
import ghidra.sleigh.grammar.*;
import ghidra.sleigh.grammar.SleighParser_SemanticParser.semantic_return;
import ghidra.util.exception.AssertException;

public class PcodeParser extends PcodeCompile {

	public final static Logger log = LogManager.getLogger(PcodeParser.class);

	private SleighBase sleigh;
	private long tempbase;
	private HashMap<String, SleighSymbol> symbolMap = new HashMap<>();

	//record symbols added so that they can be removed to reset the parser
	private HashSet<String> currentSymbols = new HashSet<>();

	protected PcodeParser(SleighBase sleigh) {

		this.sleigh = sleigh;
		initializeSymbols();
	}

	/**
	 * Build parser from a translator string
	 * @param sleighSpec sleigh translator spec including address-spaces and register definitions, see
	 * {@link SleighLanguage#buildTranslatorTag(ghidra.program.model.address.AddressFactory, long, ghidra.app.plugin.processors.sleigh.symbol.SymbolTable, boolean)}
	 * @throws JDOMException
	 */
	public PcodeParser(String sleighSpec) throws JDOMException {
		DocumentStorage store = new DocumentStorage();
		Document doc = null;
		try {
			doc = store.parseDocument(new StringBufferInputStream(sleighSpec));
		}
		catch (IOException e) {
			throw new AssertException(); // unexpected on string
		}
		store.registerTag(doc.getRootElement());

		PcodeTranslate translate = new PcodeTranslate();
		translate.initialize(store);
		sleigh = translate;
		initializeSymbols();
	}

	private void initializeSymbols() {
		tempbase = sleigh.getUniqueBase();

		Location internalLoc = Location.INTERNALLY_DEFINED;
		symbolMap.put("inst_start", new StartSymbol(internalLoc, "inst_start", getConstantSpace()));
		symbolMap.put("inst_next", new EndSymbol(internalLoc, "inst_next", getConstantSpace()));
		symbolMap.put("inst_ref", new FlowRefSymbol(internalLoc, "inst_ref", getConstantSpace()));
		symbolMap.put("inst_dest",
			new FlowDestSymbol(internalLoc, "inst_dest", getConstantSpace()));
	}

	/**
	 * Inject a symbol representing an "operand" to the pcode snippet.  This puts a placeholder in the
	 * resulting template, which gets filled in with the context specific storage locations when final
	 * p-code is generated
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

	@Override
	public long allocateTemp() {
		long base = tempbase;
		tempbase = base + SleighBase.MAX_UNIQUE_SIZE;
		return base;
	}

	@Override
	public VectorSTL<OpTpl> createMacroUse(Location location, MacroSymbol sym,
			VectorSTL<ExprTree> param) {
		throw new SleighError("Pcode snippet parsing does not support use of macros", location);
	}

	@Override
	public SleighSymbol findSymbol(String nm) {
		SleighSymbol sym = symbolMap.get(nm);
		if (sym != null) {
			return sym;
		}
		return PcodeParser.this.sleigh.findSymbol(nm);
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
						String.format("Label <%s> was placed but never used",  sym.getName())));

			}
			else if (!labsym.isPlaced()) {
				errors.add(MessageFormattingUtils.format(labsym.location,
						String.format("Label <%s> was referenced but never placed",  sym.getName())));
			}
		}
		return errors.stream().collect(Collectors.joining("  "));

	}

	private ConstructTpl buildConstructor(ConstructTpl rtl) {
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
		return rtl;
	}

	private static class PcodeTranslate extends SleighBase {

		@Override
		public void initialize(DocumentStorage store) {
			Element el = store.getTag("sleigh");
			if (el == null) {
				throw new LowlevelError("Could not find sleigh tag");
			}
			target_endian = XmlUtils.decodeBoolean(el.getAttributeValue("bigendian")) ? 1 : 0;
			alignment = XmlUtils.decodeUnknownInt(el.getAttributeValue("align"));
			long ubase = XmlUtils.decodeUnknownLong(el.getAttributeValue("uniqbase"));
			setUniqueBase(ubase);

			List<?> list = el.getChildren();
			Iterator<?> iter = list.iterator();
			Element child = (Element) iter.next();
			while (child.getName().equals("floatformat")) {
				child = (Element) iter.next(); // skip over
			}
			restoreXmlSpaces(child);

			child = (Element) iter.next();

			while ("truncate_space".equals(child.getName())) {
				// TODO: do we care about space truncations ?
				child = (Element) iter.next();
			}

			symtab.restoreXml(child, this);

			for (int i = 0; i < numSpaces(); i++) {
				AddrSpace space = getSpace(i);
				symtab.addSymbol(new SpaceSymbol(null, space));
			}
		}

		@Override
		public int instructionLength(Address baseaddr) {
			return 0;
		}

		@Override
		public int printAssembly(PrintStream s, int size, Address baseaddr) {
			return 0;
		}
	}

	public static String stringifyTemplate(ConstructTpl ctl) {

		if (ctl == null) {
			return null;
		}
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ctl.saveXml(new PrintStream(out), -1);   // for main section?
		return out.toString();
	}

	/**
	 * Compile pcode semantic statements.
	 * @param pcodeStatements
	 * @param srcFile source filename from which pcodeStatements came (
	 * @param srcLine line number in srcFile corresponding to pcodeStatements
	 * @return ConstructTpl. A null may be returned or 
	 * an exception thrown if parsing/compiling fails (see application log for errors).
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
	public VectorSTL<OpTpl> createCrossBuild(Location where, VarnodeTpl v, SectionSymbol second) {
		throw new SleighError("Pcode snippet parsing does not support use of sections", where);
	}

	@Override
	public SectionVector standaloneSection(ConstructTpl main) {
		// Create SectionVector for just the main rtl section with no named sections
		SectionVector res = new SectionVector(main, null);
		return res;
	}

	@Override
	public SectionVector firstNamedSection(ConstructTpl main, SectionSymbol sym) {
		throw new SleighError("Pcode snippet parsing does not support use of sections",
			sym.location);
	}

	@Override
	public SectionVector nextNamedSection(SectionVector vec, ConstructTpl section,
			SectionSymbol sym) {
		throw new SleighError("Pcode snippet parsing does not support use of sections",
			sym.location);
	}

	@Override
	public SectionVector finalNamedSection(SectionVector vec, ConstructTpl section) {
		throw new SleighError("Pcode snippet parsing does not support use of sections", null); // can never get here
	}
}
