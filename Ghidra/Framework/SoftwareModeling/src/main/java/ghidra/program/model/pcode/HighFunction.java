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
package ghidra.program.model.pcode;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.program.database.function.FunctionDB;
import ghidra.program.database.symbol.CodeSymbol;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 *
 *
 * High-level abstraction associated with a low level function made up of assembly instructions.
 * Based on information the decompiler has produced after working on a function.
 */
public class HighFunction extends PcodeSyntaxTree {
	public final static String DECOMPILER_TAG_MAP = "decompiler_tags";
	private Function func; // The traditional function object
	private Language language;
	private CompilerSpec compilerSpec;
	private FunctionPrototype proto; // The high-level prototype associated with the function
	private LocalSymbolMap localSymbols;
	private GlobalSymbolMap globalSymbols;
	private List<JumpTable> jumpTables;
	private List<DataTypeSymbol> protoOverrides;

	/**
	 * @param function  function associated with the higher level function abstraction.
	 * @param language  description of the processor language of the function
	 * @param compilerSpec description of the compiler that produced the function
	 * @param dtManager data type manager
	 */
	public HighFunction(Function function, Language language, CompilerSpec compilerSpec,
			PcodeDataTypeManager dtManager) {
		super(function.getProgram().getAddressFactory(), dtManager);
		func = function;
		this.language = language;
		this.compilerSpec = compilerSpec;
		AddressSpace stackSpace = function.getProgram().getAddressFactory().getStackSpace();
		localSymbols = new LocalSymbolMap(this, stackSpace);
		globalSymbols = new GlobalSymbolMap(this);
		proto = new FunctionPrototype(localSymbols, function);
		jumpTables = null;
		protoOverrides = null;
	}

	/**
	 * @return get the associated low level function
	 */
	public Function getFunction() {
		return func;
	}

	/**
	 * Get the id with the associated function symbol, if it exists.
	 * Otherwise return a dynamic id based on the entry point.
	 * @return the symbol id, or possibly a dynamic id
	 */
	public long getID() {
		if (func instanceof FunctionDB) {
			return func.getSymbol().getID();
		}
		return func.getProgram().getSymbolTable().getDynamicSymbolID(func.getEntryPoint());
	}

	/**
	 * @return get the language parser used to disassemble
	 */
	public Language getLanguage() {
		return language;
	}

	public CompilerSpec getCompilerSpec() {
		return compilerSpec;
	}

	/**
	 * @return the function prototype for the function (how things are passed/returned)
	 */
	public FunctionPrototype getFunctionPrototype() {
		return proto;
	}

	/**
	 * @return an array of jump table definitions found for this function decompilation
	 */
	public JumpTable[] getJumpTables() {
		if (jumpTables == null) {
			return new JumpTable[0];
		}
		JumpTable[] res = new JumpTable[jumpTables.size()];
		return jumpTables.toArray(res);
	}

	/**
	 * @return the local variable map describing the defined local variables
	 */
	public LocalSymbolMap getLocalSymbolMap() {
		return localSymbols;
	}

	/**
	 * @return a map describing global variables accessed by this function
	 */
	public GlobalSymbolMap getGlobalSymbolMap() {
		return globalSymbols;
	}

	public HighSymbol getMappedSymbol(Address addr, Address pcaddr) {
		return localSymbols.findLocal(addr, pcaddr);
	}

	@Override
	public HighSymbol getSymbol(long symbolId) {
		return localSymbols.getSymbol(symbolId);
	}

	/**
	 * Populate the information for the HighFunction from the information in the
	 * Function object.
	 *
	 * @param overrideExtrapop is the value to use if extrapop is overridden
	 * @param includeDefaultNames is true if default symbol names should be considered locked
	 * @param doOverride is true if extrapop is overridden
	 */
	public void grabFromFunction(int overrideExtrapop, boolean includeDefaultNames,
			boolean doOverride) {
		localSymbols.grabFromFunction(includeDefaultNames); // Locals must be read first
		proto.grabFromFunction(func, overrideExtrapop, doOverride);
		jumpTables = null;
		protoOverrides = null;
		grabOverrides();
	}

	/**
	 * Check the symbol space for objects that indicate specific overrides to decompiler analysis:
	 *      a) switch flow
	 */
	private void grabOverrides() {
		if (!(func instanceof FunctionDB)) {
			return; // undefined function
		}
		SymbolTable symtab = func.getProgram().getSymbolTable();
		Namespace space = findOverrideSpace(func);
		if (space == null) {
			return;
		}
		SymbolIterator iter = symtab.getSymbols(space);
		while (iter.hasNext()) {
			Symbol sym = iter.next();
			String nm = sym.getName();
			if (nm.length() < 3) {
				continue;
			}
			nm = nm.substring(0, 3);
			if (nm.equals("jmp")) {
				Object obj = sym.getObject();
				if (obj instanceof Namespace) {
					JumpTable jumpTab = JumpTable.readOverride((Namespace) obj, symtab);
					if (jumpTab != null) {
						if (jumpTables == null) {
							jumpTables = new ArrayList<>();
						}
						jumpTables.add(jumpTab);
					}
				}
			}
			else if (nm.equals("prt")) {
				if (sym.getSymbolType() == SymbolType.LABEL) {
					DataTypeSymbol protover = HighFunctionDBUtil.readOverride(sym);
					if (protover != null) {
						if (protoOverrides == null) {
							protoOverrides = new ArrayList<>();
						}
						protoOverrides.add(protover);
					}
				}
			}
		}
	}

	@Override
	public Varnode newVarnode(int sz, Address addr) {
		// translate into function overlay space if possible
		addr = func.getEntryPoint().getAddressSpace().getOverlayAddress(addr);
		return super.newVarnode(sz, addr);
	}

	@Override
	public Varnode newVarnode(int sz, Address addr, int id) {
		// translate into function overlay space if possible
		addr = func.getEntryPoint().getAddressSpace().getOverlayAddress(addr);
		return super.newVarnode(sz, addr, id);
	}

	private void decodeHigh(Decoder decoder) throws PcodeXMLException {
		int el = decoder.openElement(ELEM_HIGH);
		String classstring = decoder.readString(ATTRIB_CLASS);
		HighVariable var;
		switch (classstring.charAt(0)) {
			case 'o':
				var = new HighOther(this);
				break;
			case 'g':
				var = new HighGlobal(this);
				break;
			case 'l':
				var = new HighLocal(this);
				break;
			case 'p':
				var = new HighParam(this);
				break;
			case 'c':
				var = new HighConstant(this);
				break;
			default:
				throw new PcodeXMLException("Unknown HighVariable class string: " + classstring);
		}
		var.decode(decoder);
		decoder.closeElement(el);
	}

	private void decodeHighlist(Decoder decoder) throws PcodeXMLException {
		int el = decoder.openElement(ELEM_HIGHLIST);
		while (decoder.peekElement() != 0) {
			decodeHigh(decoder);
		}
		decoder.closeElement(el);
	}

	@Override
	public void decode(Decoder decoder) throws PcodeXMLException {
		int start = decoder.openElement(ELEM_FUNCTION);
		String name = decoder.readString(ATTRIB_NAME);
		if (!func.getName().equals(name)) {
			throw new PcodeXMLException("Function name mismatch: " + func.getName() + " + " + name);
		}
		for (;;) {
			int subel = decoder.peekElement();
			if (subel == 0) {
				break;
			}
			if (subel == ELEM_ADDR.id()) {
				Address addr = AddressXML.decode(decoder);
				addr = func.getEntryPoint().getAddressSpace().getOverlayAddress(addr);
				if (!func.getEntryPoint().equals(addr)) {
					throw new PcodeXMLException("Mismatched address in function tag");
				}
			}
			else if (subel == ELEM_PROTOTYPE.id()) {
				proto.decodePrototype(decoder, getDataTypeManager());
			}
			else if (subel == ELEM_LOCALDB.id()) {
				localSymbols.decodeScope(decoder);
			}
			else if (subel == ELEM_AST.id()) {
				super.decode(decoder);
			}
			else if (subel == ELEM_HIGHLIST.id()) {
				decodeHighlist(decoder);
			}
			else if (subel == ELEM_JUMPTABLELIST.id()) {
				decodeJumpTableList(decoder);
			}
			else if (subel == ELEM_OVERRIDE.id()) {
				// Do nothing with override at the moment
				decoder.skipElement();
			}
			else if (subel == ELEM_SCOPE.id()) {
				// This must be a subscope of the local scope
				// Currently this can only hold static variables of the function
				// which ghidra already knows about
				decoder.skipElement();
			}
			else {
				throw new PcodeXMLException("Unknown element in function");
			}
		}
		decoder.closeElement(start);
	}

	/**
	 * Decode the Jump Table list for this function from the stream
	 *
	 * @param decoder is the stream decoder
	 * @throws PcodeXMLException for invalid encodings
	 */
	private void decodeJumpTableList(Decoder decoder) throws PcodeXMLException {
		int el = decoder.openElement(ELEM_JUMPTABLELIST);
		while (decoder.peekElement() != 0) {
			JumpTable table = new JumpTable(func.getEntryPoint().getAddressSpace());
			table.decode(decoder);
			if (!table.isEmpty()) {
				if (jumpTables == null) {
					jumpTables = new ArrayList<>();
				}
				jumpTables.add(table);
			}
		}
		decoder.closeElement(el);
	}

	protected Address getPCAddress(Varnode rep) {
		Address pcaddr = null;
		if (!rep.isAddrTied()) {
			pcaddr = rep.getPCAddress();
			if (pcaddr == Address.NO_ADDRESS) {
				try {
					pcaddr = func.getEntryPoint().add(-1);
				}
				catch (AddressOutOfBoundsException e) {
					pcaddr = func.getEntryPoint();
				}
			}
		}
		return pcaddr;
	}

	/**
	 * If a HighVariable consists of more than one (forced) merge group, split out the group
	 * that contains vn as a separate HighVariable. Otherwise just return the original high.
	 * @param high is the HighVariable to split
	 * @param vn is a representative of the merge group to split out
	 * @return a HighVariable containing just the forced merge group of vn
	 * @throws PcodeException if the split can't be performed
	 */
	public HighVariable splitOutMergeGroup(HighVariable high, Varnode vn) throws PcodeException {
		try {
			ArrayList<Varnode> newinst = new ArrayList<>();
			ArrayList<Varnode> oldinst = new ArrayList<>();
			short ourgroup = vn.getMergeGroup();
			Varnode[] curinst = high.getInstances();
			for (Varnode curvn : curinst) {
				if (curvn.getMergeGroup() == ourgroup) {
					newinst.add(curvn);
				}
				else {
					oldinst.add(curvn);
				}
			}
			if (oldinst.size() == 0) {
				return high; // Everybody is in the same group
			}
			if (!(high instanceof HighLocal)) {
				throw new PcodeException(
					"Variable " + high.getName() + " is speculatively merged but not a local");
			}
			HighLocal highloc = (HighLocal) high;
			Varnode[] newinstarray = new Varnode[newinst.size()];
			newinst.toArray(newinstarray);
			Varnode[] oldinstarray = new Varnode[oldinst.size()];
			oldinst.toArray(oldinstarray);
			Varnode oldrep = high.getRepresentative();
			HighLocal reslocal;
			HighVariable resremain;
			HighSymbol sym;
			if (oldrep.getMergeGroup() == ourgroup) {
				// Here the requested vn is in the same merge group as the original representative
				// So we keep the original representative and symbol
				if (high instanceof HighParam) {
					return high; // just do ordinary param rename
				}
				vn = oldrep;
				oldrep = oldinstarray[0];
				sym = highloc.getSymbol(); // Keep original symbol with new higher
				reslocal = new HighLocal(highloc.getDataType(), highloc.getRepresentative(), null,
					highloc.getPCAddress(), sym);

				// Shove the remaining varnodes into a HighOther just to be consistent.
				resremain = new HighOther(highloc.getDataType(),
					new Varnode(oldrep.getAddress(), highloc.getSize()), null,
					oldrep.getPCAddress(), this);
			}
			else {
				// Here the requested vn is in a different merge group from the original representative
				// So we create a new symbol based on vn

				// Note that we don't need to distinguish between unique,register,ram etc. and don't
				// need to separate out first use versus mapped use.  When the high local is written
				// to database, these issues will be resolved at that point.
				sym = localSymbols.newMappedSymbol(0, highloc.getName(), highloc.getDataType(),
					buildStorage(vn), vn.getPCAddress(), -1);
				reslocal = new HighLocal(highloc.getDataType(), vn, null, vn.getPCAddress(), sym);

				resremain = highloc; // Keep remaining varnodes in old high
			}
			sym.setHighVariable(reslocal);
			reslocal.attachInstances(newinstarray, vn);
			for (Varnode element : newinstarray) {
				((VarnodeAST) element).setHigh(reslocal);
			}

			resremain.attachInstances(oldinstarray, oldrep);
			for (Varnode element : oldinstarray) {
				((VarnodeAST) element).setHigh(resremain);
			}
			return reslocal;
		}
		catch (InvalidInputException e) {
			throw new PcodeXMLException("Bad storage node", e);
		}
	}

	/**
	 * Encode this HighFunction to a stream. The size describes how many bytes starting from the
	 * entry point are used by the function, but this doesn't need to be strictly accurate as it
	 * is only used to associate the function with addresses near its entry point.
	 * @param encoder is the stream encoder
	 * @param id is the id associated with the function symbol
	 * @param namespace is the namespace containing the function symbol
	 * @param entryPoint pass null to use the function entryPoint, pass an address to force an entry point
	 * @param size describes how many bytes the function occupies as code
	 * @throws IOException for errors in the underlying stream
	 */
	public void encode(Encoder encoder, long id, Namespace namespace, Address entryPoint, int size)
			throws IOException {
		// Functions aren't necessarily contiguous with the smallest address being the entry point
		// So size needs to be smaller than size of the contiguous chunk containing the entry point
		encoder.openElement(ELEM_FUNCTION);
		if (id != 0) {
			encoder.writeUnsignedInteger(ATTRIB_ID, id);
		}
		encoder.writeString(ATTRIB_NAME, func.getName());
		encoder.writeSignedInteger(ATTRIB_SIZE, size);
		if (func.isInline()) {
			encoder.writeBool(ATTRIB_INLINE, true);
		}
		if (func.hasNoReturn()) {
			encoder.writeBool(ATTRIB_NORETURN, true);
		}
		if (entryPoint == null) {
			AddressXML.encode(encoder, func.getEntryPoint());
		}
		else {
			AddressXML.encode(encoder, entryPoint);		// Address is forced on XML
		}
		localSymbols.encodeLocalDb(encoder, namespace);
		proto.encodePrototype(encoder, getDataTypeManager());
		if ((jumpTables != null) && (jumpTables.size() > 0)) {
			encoder.openElement(ELEM_JUMPTABLELIST);
			for (JumpTable jumpTable : jumpTables) {
				jumpTable.encode(encoder);
			}
			encoder.closeElement(ELEM_JUMPTABLELIST);
		}
		boolean hasOverrideTag = ((protoOverrides != null) && (protoOverrides.size() > 0));
		if (hasOverrideTag) {
			encoder.openElement(ELEM_OVERRIDE);
			PcodeDataTypeManager dtmanage = getDataTypeManager();
			for (DataTypeSymbol sym : protoOverrides) {
				Address addr = sym.getAddress();
				FunctionPrototype fproto = new FunctionPrototype(
					(FunctionSignature) sym.getDataType(), compilerSpec, false);
				encoder.openElement(ELEM_PROTOOVERRIDE);
				AddressXML.encode(encoder, addr);
				fproto.encodePrototype(encoder, dtmanage);
				encoder.closeElement(ELEM_PROTOOVERRIDE);
			}
			encoder.closeElement(ELEM_OVERRIDE);
		}
		encoder.closeElement(ELEM_FUNCTION);
	}

	public static Namespace findOverrideSpace(Function func) {
		SymbolTable symtab = func.getProgram().getSymbolTable();
		return findNamespace(symtab, func, "override");
	}

	public static Namespace findCreateOverrideSpace(Function func) {
		SymbolTable symtab = func.getProgram().getSymbolTable();
		return findCreateNamespace(symtab, func, "override");
	}

	public static Namespace findNamespace(SymbolTable symtab, Namespace parent, String name) {
		return symtab.getNamespace(name, parent);
	}

	public static void createLabelSymbol(SymbolTable symtab, Address addr, String name,
			Namespace namespace, SourceType source, boolean useLocalNamespace)
			throws InvalidInputException {
		if (namespace == null && useLocalNamespace) {
			namespace = symtab.getNamespace(addr);
		}
		symtab.createLabel(addr, name, namespace, source);
	}

	public static void deleteSymbol(SymbolTable symtab, Address addr, String name, Namespace space)
			throws InvalidInputException {
		Symbol s = symtab.getSymbol(name, addr, space);
		if (s == null) {
			throw new InvalidInputException("Symbol " + name + " not found!");
		}
		if (s.getSource() == SourceType.DEFAULT) {
			throw new InvalidInputException(
				"Deleting the default symbol \"" + name + "\" @ " + addr + " is not allowed.");
		}

		boolean success = symtab.removeSymbolSpecial(s);
		if (!success) {
			throw new InvalidInputException(
				"Couldn't delete the symbol \"" + name + "\" @ " + addr + ".");
		}
	}

	public static boolean clearNamespace(SymbolTable symtab, Namespace space)
			throws InvalidInputException {
		SymbolIterator iter = symtab.getSymbols(space);
		ArrayList<Address> addrlist = new ArrayList<>();
		ArrayList<String> namelist = new ArrayList<>();
		while (iter.hasNext()) {
			Symbol sym = iter.next();
			if (!(sym instanceof CodeSymbol)) {
				return false;
			}
			addrlist.add(sym.getAddress());
			namelist.add(sym.getName());
		}
		for (int i = 0; i < addrlist.size(); ++i) {
			deleteSymbol(symtab, addrlist.get(i), namelist.get(i), space);
		}
		return true;
	}

	public static Namespace findCreateNamespace(SymbolTable symtab, Namespace parentspace,
			String name) {
		Namespace res = findNamespace(symtab, parentspace, name);
		if (res == null) {
			try {
				return symtab.createNameSpace(parentspace, name, SourceType.USER_DEFINED);
			}
			catch (DuplicateNameException e) {
				return null;
			}
			catch (InvalidInputException e) {
				return null;
			}
		}
		return res;
	}

	/**
	 * The decompiler treats some namespaces as equivalent to the "global" namespace.
	 * Return true if the given namespace is treated as equivalent.
	 * @param namespace is the namespace
	 * @return true if equivalent
	 */
	static final public boolean collapseToGlobal(Namespace namespace) {
		if (namespace instanceof Library) {
			return true;
		}
		return false;
	}

	/**
	 * Encode &lt;parent&gt; element to the stream describing the formal path elements
	 * from the root (global) namespace up to the given namespace
	 * @param encoder is the stream encoder
	 * @param namespace is the namespace being described
	 * @throws IOException for errors in the underlying stream
	 */
	static public void encodeNamespace(Encoder encoder, Namespace namespace) throws IOException {
		encoder.openElement(ELEM_PARENT);
		if (namespace != null) {
			ArrayList<Namespace> arr = new ArrayList<>();
			Namespace curspc = namespace;
			while (curspc != null) {
				arr.add(0, curspc);
				if (collapseToGlobal(curspc)) {
					break;		// Treat library namespace as root
				}
				curspc = curspc.getParentNamespace();
			}
			encoder.openElement(ELEM_VAL);	// Force global scope to have empty name
			encoder.closeElement(ELEM_VAL);
			for (int i = 1; i < arr.size(); ++i) {
				Namespace curScope = arr.get(i);
				encoder.openElement(ELEM_VAL);
				encoder.writeUnsignedInteger(ATTRIB_ID, curScope.getID());
				encoder.writeString(ATTRIB_CONTENT, curScope.getName());
				encoder.closeElement(ELEM_VAL);
			}
		}
		encoder.closeElement(ELEM_PARENT);
	}

	/**
	 * @param tagname -- Name of tag to search for
	 * @param doc -- String through which to search for tags
	 * @return all characters between beginning and ending XML tags, excluding tags themselves
	 */
	static public String tagFindExclude(String tagname, String doc) {
		if (doc == null) {
			return null;
		}
		int length = tagname.length();
		int bindex = doc.indexOf("<" + tagname);
		if (bindex == -1) {
			return null;
		}
		if (bindex + length + 3 > doc.length()) {
			return null;
		}
		if (doc.charAt(bindex + length + 1) == '/') {
			return "";
		}
		int eindex = doc.indexOf("</" + tagname + ">");
		if (eindex == -1) {
			return null;
		}
		return doc.substring(bindex + length + 2, eindex);
	}
}
