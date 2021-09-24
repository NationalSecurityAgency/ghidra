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
package ghidra.app.decompiler;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.ArrayList;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.*;
import org.xml.sax.helpers.DefaultHandler;

import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsImpl;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.lang.ConstantPool.Record;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.util.xml.XmlUtilities;

/**
 * 
 *
 * Routines that the decompiler invokes to gather info during decompilation of a
 * function.
 */
public class DecompileCallback {

	public final static int MAX_SYMBOL_COUNT = 16;

	/**
	 * Data returned for a query about strings
	 */
	public static class StringData {
		boolean isTruncated;		// Did we truncate the string
		public byte[] byteData;		// The UTF8 encoding of the string
	}

	private DecompileDebug debug;
	private Program program;
	private Listing listing;
	private UniqueAddressFactory uniqueFactory;
	private Function cachedFunction;
	private AddressSet undefinedBody;
	private Address funcEntry;
	private AddressSpace overlaySpace;		// non-null if function being decompiled is in an overlay
	private int default_extrapop;
	private Language pcodelanguage;
	private CompilerSpec pcodecompilerspec;
	private AddressFactory addrfactory;
	private ConstantPool cpool;
	private PcodeDataTypeManager dtmanage;
	private Charset utf8Charset;
	private String nativeMessage;

	private InstructionBlock lastPseudoInstructionBlock;
	private Disassembler pseudoDisassembler;

	public DecompileCallback(Program prog, Language language, CompilerSpec compilerSpec,
			PcodeDataTypeManager dt) {
		program = prog;
		pcodelanguage = language;
		uniqueFactory = new UniqueAddressFactory(prog.getAddressFactory(), language);
		pcodecompilerspec = compilerSpec;
		listing = program.getListing();
		addrfactory = program.getAddressFactory();
		dtmanage = dt;
		default_extrapop = pcodecompilerspec.getDefaultCallingConvention().getExtrapop();
		cpool = null;
		nativeMessage = null;
		debug = null;
		utf8Charset = Charset.availableCharsets().get(CharsetInfo.UTF8);
	}

	private static SAXParser getSAXParser() throws PcodeXMLException {
		try {
			SAXParserFactory saxParserFactory = XmlUtilities.createSecureSAXParserFactory(false);
			saxParserFactory.setFeature("http://xml.org/sax/features/namespaces", false);
			saxParserFactory.setFeature("http://xml.org/sax/features/validation", false);
			return saxParserFactory.newSAXParser();
		}
		catch (Exception e) {
			Msg.error(DecompileCallback.class, e.getMessage());
			throw new PcodeXMLException("Failed to instantiate XML parser", e);
		}
	}

	/**
	 * Establish function and debug context for next decompilation
	 * 
	 * @param func is the function to be decompiled
	 * @param entry is the function's entry address
	 * @param dbg is the debugging context (or null)
	 */
	public void setFunction(Function func, Address entry, DecompileDebug dbg) {
		cachedFunction = func;
		undefinedBody = null;
		if (func instanceof UndefinedFunction) {
			undefinedBody = new AddressSet(func.getBody());
		}
		funcEntry = entry;
		AddressSpace spc = funcEntry.getAddressSpace();
		overlaySpace = spc.isOverlaySpace() ? spc : null;
		debug = dbg;
		if (debug != null) {
			debug.setPcodeDataTypeManager(dtmanage);
		}
		nativeMessage = null; // Clear last message
		lastPseudoInstructionBlock = null;
		if (pseudoDisassembler != null) {
			pseudoDisassembler.resetDisassemblerContext();
		}
		uniqueFactory.reset();
	}

	/**
	 * @return the last message from the decompiler
	 */
	public String getNativeMessage() {
		return nativeMessage;
	}

	/**
	 * Cache a message returned by the decompiler process
	 * 
	 * @param msg is the message
	 */
	void setNativeMessage(String msg) {
		nativeMessage = msg;
	}

	public synchronized ArrayList<String> readXMLNameList(String xml) throws PcodeXMLException {
		try {
			NameListHandler nmHandler = new NameListHandler();
			getSAXParser().parse(new InputSource(new StringReader(xml)), nmHandler);
			return nmHandler.getList();
		}
		catch (SAXException e1) {
			throw new PcodeXMLException("Problem parsing list string " + xml, e1);
		}
		catch (IOException e1) {
			throw new PcodeXMLException("Problem parsing list string " + xml, e1);
		}
	}

	public byte[] getBytes(String addrxml) {
		try {
			Address addr = AddressXML.readXML(addrxml, addrfactory);
			int size = AddressXML.readXMLSize(addrxml);
			if (overlaySpace != null) {
				addr = overlaySpace.getOverlayAddress(addr);
			}
			if (addr == Address.NO_ADDRESS) {
				throw new PcodeXMLException("Address does not physically map");
			}
			if (addr.isRegisterAddress()) {
				return null;
			}
			byte[] resbytes = new byte[size];
			int bytesRead = program.getMemory().getBytes(addr, resbytes, 0, size);
			if (debug != null) {
				if (bytesRead != size) {
					byte[] debugBytes = new byte[bytesRead];
					System.arraycopy(resbytes, 0, debugBytes, 0, bytesRead);
					debug.getBytes(addr, debugBytes);
				}
				else {
					debug.getBytes(addr, resbytes);
				}
			}
			return resbytes;
		}
		catch (MemoryAccessException e) {
			Msg.warn(this, "Decompiling " + funcEntry + ": " + e.getMessage());
		}
		catch (PcodeXMLException e) {
			Msg.error(this, "Decompiling " + funcEntry + ": " + e.getMessage());
		}
		catch (Exception e) {
			Msg.error(this,
				"Decompiling " + funcEntry + ", error while accessing bytes: " + e.getMessage(), e);
		}
		return null;
	}

	/**
	 * Collect any/all comments for the function starting at the indicated
	 * address
	 * 
	 * @param addrstring is the XML rep of function address
	 * @param types is the string encoding of the comment type flags
	 * @return XML document describing comments
	 */
	public String getComments(String addrstring, String types) {
		Address addr;
		int flags;
		try {
			addr = AddressXML.readXML(addrstring, addrfactory);
			if (overlaySpace != null) {
				addr = overlaySpace.getOverlayAddress(addr);
			}
		}
		catch (PcodeXMLException e) {
			Msg.error(this, "Decompiling " + funcEntry + ": " + e.getMessage());
			return null;
		}
		flags = SpecXmlUtils.decodeInt(types);
		Function func = getFunctionAt(addr);
		if (func == null) {
			return null;
		}
		AddressSetView addrset = func.getBody();
		StringBuilder buf = new StringBuilder();
		buf.append("<commentdb>\n");
		if ((flags & 8) != 0) {
			generateHeaderCommentXML(func, buf);
		}
		if ((flags & 1) != 0) {
			generateCommentXML(addrset, addr, buf, CodeUnit.EOL_COMMENT);
		}
		if ((flags & 2) != 0) {
			generateCommentXML(addrset, addr, buf, CodeUnit.PRE_COMMENT);
		}
		if ((flags & 4) != 0) {
			generateCommentXML(addrset, addr, buf, CodeUnit.POST_COMMENT);
		}
		if ((flags & 8) != 0) {
			generateCommentXML(addrset, addr, buf, CodeUnit.PLATE_COMMENT);
		}
		buf.append("</commentdb>\n");
		String res = buf.toString();
		if (debug != null) {
			debug.getComments(res);
		}
		return res;
	}

	public PackedBytes getPcodePacked(String addrstring) {
		Address addr = null;
		try {
			addr = AddressXML.readXML(addrstring, addrfactory);
			if (overlaySpace != null) {
				addr = overlaySpace.getOverlayAddress(addr);
			}
		}
		catch (PcodeXMLException e) {
			Msg.error(this, "Decompiling " + funcEntry + ": " + e.getMessage());
			return null;
		}
		try {
			Instruction instr = getInstruction(addr);
			if (instr == null) {
				return null;
			}
			if (undefinedBody != null) {
				undefinedBody.addRange(instr.getMinAddress(), instr.getMaxAddress());
				cachedFunction.setBody(undefinedBody);
			}
			if (debug != null) {
				debug.getPcode(addr, instr);
				FlowOverride fo = instr.getFlowOverride();
				if (fo != FlowOverride.NONE) {
					debug.addFlowOverride(addr, fo);
				}
			}

			PackedBytes pcode = instr.getPrototype()
					.getPcodePacked(instr.getInstructionContext(),
						new InstructionPcodeOverride(instr), uniqueFactory);

			return pcode;
		}
		catch (UsrException e) {
			Msg.warn(this,
				"Decompiling " + funcEntry + ", pcode error at " + addr + ": " + e.getMessage());
		}
		catch (Exception e) {
			Msg.error(this,
				"Decompiling " + funcEntry + ", pcode error at " + addr + ": " + e.getMessage(), e);
		}
		return null;

	}

	/**
	 * Build an XML representation of all the pcode op's a given Instruction is
	 * defined to perform.
	 * 
	 * @param ops pcode ops
	 * @param fallthruoffset number of bytes after instruction start that pcode
	 *            flow falls into
	 * @param paramshift special instructions for injection use
	 * @param addrFactory is the address factory for recovering address space names
	 * @return XML document as string representing all the p-code
	 */
	public static String buildInstruction(PcodeOp[] ops, int fallthruoffset, int paramshift,
			AddressFactory addrFactory) {
		StringBuilder resBuf = new StringBuilder();
		if ((ops.length == 1) && (ops[0].getOpcode() == PcodeOp.UNIMPLEMENTED)) {
			resBuf.append("<unimpl");
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "offset", fallthruoffset);
			resBuf.append("/>\n");
			return resBuf.toString();
		}
		resBuf.append("<inst");
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "offset", fallthruoffset);
		if (paramshift != 0) {
			SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "paramshift", paramshift);
		}
		resBuf.append('>');
		for (PcodeOp op : ops) {
			op.buildXML(resBuf, addrFactory);
		}
		resBuf.append("</inst>\n");
		return resBuf.toString();
	}

	public String getPcodeInject(String nm, String context, int type) {
		PcodeInjectLibrary snippetLibrary = pcodecompilerspec.getPcodeInjectLibrary();

		InjectPayload payload = snippetLibrary.getPayload(type, nm);
		if (payload == null) {
			Msg.warn(this, "Decompiling " + funcEntry + ", no pcode inject with name: " + nm);
			return null; // No fixup associated with this name
		}
		InjectContext con = snippetLibrary.buildInjectContext();
		PcodeOp[] pcode;
		try {
			con.restoreXml(getSAXParser(), context, addrfactory);
		}
		catch (PcodeXMLException e) {
			Msg.error(this, "Decompiling " + funcEntry + ": " + e.getMessage());
			return null;
		}
		try {
			int fallThruOffset;
			if (payload.getType() == InjectPayload.EXECUTABLEPCODE_TYPE) {
				// Executable p-code has no underlying instruction address and
				// does (should) not use the inst_start, inst_next symbols that need
				// to know about it.
				fallThruOffset = 4;		// Provide a dummy length for the XML doc
			}
			else {
				Instruction instr = getInstruction(con.baseAddr);
				if (instr == null) {
					Msg.warn(this, "Decompiling " + funcEntry + ", pcode inject error at " +
						con.baseAddr + ": instruction not found");
					return null;
				}

				// get next inst addr for inst_next pcode variable
				fallThruOffset = instr.getDefaultFallThroughOffset();
				con.nextAddr = con.baseAddr.add(fallThruOffset);

				con.refAddr = null;
				for (Reference ref : program.getReferenceManager()
						.getReferencesFrom(con.baseAddr)) {
					if (ref.isPrimary() && ref.getReferenceType().isCall()) {
						con.refAddr = ref.getToAddress();
						break;
					}
				}
			}
			pcode = payload.getPcode(program, con);
			if (pcode == null) {
				return null; // Just return a null string, which should let the decompiler exit gracefully
			}
			String finalPayload =
				buildInstruction(pcode, fallThruOffset, payload.getParamShift(), addrfactory);
			if (debug != null) {
				debug.addInject(con.baseAddr, nm, type, finalPayload);
			}
			return finalPayload;
		}
		catch (UnknownInstructionException e) {
			Msg.warn(this, "Decompiling " + funcEntry + ", pcode inject error at " + con.baseAddr +
				": " + e.getMessage());
		}
		catch (Exception e) {
			Msg.error(this, "Decompiling " + funcEntry + ", pcode inject error at " + con.baseAddr +
				": " + e.getMessage(), e);
		}
		return null;
	}

	public String getCPoolRef(long[] refs) throws IOException {
		if (cpool == null) {
			cpool = pcodecompilerspec.getPcodeInjectLibrary().getConstantPool(program);
		}
		Record record = cpool.getRecord(refs);
		String res = record.build(refs[0], dtmanage).toString();
		if (debug != null) {
			debug.getCPoolRef(res, refs);
		}
		return res;
	}

	private Instruction getInstruction(Address addr) throws UnknownInstructionException {
		Instruction instr = listing.getInstructionAt(addr);
		if (instr == null) {
			instr = pseudoDisassemble(addr);
		}
		return instr;
	}

	private Instruction pseudoDisassemble(Address addr) throws UnknownInstructionException {

		Instruction instr;

		if (lastPseudoInstructionBlock != null) {
			instr = lastPseudoInstructionBlock.getInstructionAt(addr);
			if (instr != null) {
				return instr;
			}
			InstructionError error = lastPseudoInstructionBlock.getInstructionConflict();
			if (error != null && addr.equals(error.getInstructionAddress())) {
				throw new UnknownInstructionException(error.getConflictMessage());
			}
			lastPseudoInstructionBlock = null;
		}

		if (pseudoDisassembler == null) {
			pseudoDisassembler = Disassembler.getDisassembler(program, false, false, false,
				TaskMonitor.DUMMY, msg -> {
					// TODO: Should we log errors?
				});
		}

		RegisterValue entryContext = null;
		ProgramContext programContext = program.getProgramContext();
		Register baseContextRegister = programContext.getBaseContextRegister();
		if (baseContextRegister != null) {
			entryContext = programContext.getRegisterValue(baseContextRegister, funcEntry);
		}

		lastPseudoInstructionBlock =
			pseudoDisassembler.pseudoDisassembleBlock(addr, entryContext, 64);
		if (lastPseudoInstructionBlock != null) {
			InstructionError error = lastPseudoInstructionBlock.getInstructionConflict();				// Look for zero-byte run first
			if (error != null &&
				error.getConflictMessage().startsWith("Maximum run of Zero-Byte")) {
				throw new UnknownInstructionException(error.getConflictMessage());		// Don't return any of the zero-byte instructions
			}
			instr = lastPseudoInstructionBlock.getInstructionAt(addr);
			if (instr != null) {
				return instr;
			}
			if (error != null && addr.equals(error.getInstructionAddress())) {
				throw new UnknownInstructionException(error.getConflictMessage());
			}
			if (MemoryBlock.isExternalBlockAddress(addr, program)) {
				throw new UnknownInstructionException(
					"Unable to disassemble EXTERNAL block location: " + addr);
			}
		}
		throw new UnknownInstructionException("Invalid instruction address (improperly aligned)");
	}

	public String getSymbol(String addrstring) { // Return first symbol name at this address
		Address addr;
		try {
			addr = AddressXML.readXML(addrstring, addrfactory);
			if (overlaySpace != null) {
				addr = overlaySpace.getOverlayAddress(addr);
			}
		}
		catch (PcodeXMLException e) {
			Msg.error(this, "Decompiling " + funcEntry + ": " + e.getMessage());
			return null;
		}
		try {
			Symbol sym = program.getSymbolTable().getPrimarySymbol(addr);
			if (sym == null) {
				return null;
			}
			String res = getSymbolName(sym);
			if (debug != null) {
				debug.getCodeSymbol(addr, sym.getID(), res, sym.getParentNamespace());
			}

			return res;
		}
		catch (Exception e) {
			Msg.error(this,
				"Decompiling " + funcEntry + ", error while accessing symbol: " + e.getMessage(),
				e);
		}
		return null;
	}

	private String getSymbolName(Symbol sym) {
		// TODO Added as a temporary measure until proper C name mangling is implemented
		// For now we will assume that it is highly unlikely that this approach will produce a
		// duplicate name to the decompiler.
		String prefix = getNamespacePrefix(sym.getParentNamespace());
		if (prefix != null) {
			return prefix + "_" + sym.getName();
		}
		return sym.getName();
	}

	private Namespace getNameSpaceByID(long id) {
		Symbol namespaceSym = program.getSymbolTable().getSymbol(id);
		if (namespaceSym == null) {
			return null;
		}
		Object namespace = namespaceSym.getObject();
		if (namespace instanceof Namespace) {
			return (Namespace) namespace;
		}
		return null;
	}

	private String getNamespacePrefix(Namespace ns) {
		if (ns.getID() == Namespace.GLOBAL_NAMESPACE_ID) {
			return null;
		}
		if (ns instanceof Function && ((Function) ns).getEntryPoint().equals(funcEntry)) {
			return null;
		}
		String name = ns.getName();
		String parentName = getNamespacePrefix(ns.getParentNamespace());
		if (parentName != null) {
			return parentName + "_" + name;
		}
		return name;
	}

	/**
	 * Decide if a given name is used by any namespace between a starting namespace
	 * and a stopping namespace.  I.e. check for a name collision along a specific namespace path.
	 * Currently, Ghidra is inefficient at calculating this perfectly, so this routine calculates
	 * an approximation that can occasionally indicate a collision when there isn't.
	 * @param name is the given name to check for collisions
	 * @param startId is the id specifying the starting namespace
	 * @param stopId is the id specifying the stopping namespace
	 * @return true if the name (likely) occurs in one of the namespaces on the path
	 */
	public boolean isNameUsed(String name, long startId, long stopId) {
		Namespace namespace = getNameSpaceByID(startId);
		int pathSize = 0;
		Namespace curspace = namespace;
		long curId = namespace.getID();
		while (curId != stopId && curId != 0 && !HighFunction.collapseToGlobal(curspace)) {
			pathSize += 1;
			curspace = curspace.getParentNamespace();
			curId = curspace.getID();
		}
		long path[] = new long[pathSize];
		curspace = namespace;
		path[0] = startId;
		for (int i = 1; i < pathSize; ++i) {
			curspace = curspace.getParentNamespace();
			path[i] = curspace.getID();
		}
		int count = 0;
		SymbolIterator iter = program.getSymbolTable().getSymbols(name);
		for (;;) {
			if (!iter.hasNext()) {
				break;
			}
			count += 1;
			if (count > MAX_SYMBOL_COUNT) {
				break;
			}
			Namespace symSpace = iter.next().getParentNamespace();
			long id = symSpace.getID();
			if (id == Namespace.GLOBAL_NAMESPACE_ID) {
				continue;	// Common case we know can't match anything in path
			}
			for (int i = 0; i < pathSize; ++i) {
				if (path[i] == id) {
					if (debug != null) {
						debug.nameIsUsed(symSpace, name);
					}
					return true;
				}
			}
		}
		return (count > MAX_SYMBOL_COUNT);
	}

	/**
	 * Return an XML description of the formal namespace path to the given namespace
	 * @param id is the ID of the given namespace
	 * @return a parent XML tag
	 */
	public String getNamespacePath(long id) {
		Namespace namespace = getNameSpaceByID(id);
		StringBuilder buf = new StringBuilder();
		HighFunction.createNamespaceTag(buf, namespace);
		if (debug != null) {
			debug.getNamespacePath(namespace);
		}
		return buf.toString();
	}

	private void generateHeaderCommentXML(Function func, StringBuilder buf) {
		Address addr = func.getEntryPoint();
		String text = listing.getComment(CodeUnit.PLATE_COMMENT, addr);
		if (text != null) {
			buf.append("<comment");
			SpecXmlUtils.encodeStringAttribute(buf, "type", "header");
			buf.append(">\n");
			AddressXML.buildXML(buf, addr);
			AddressXML.buildXML(buf, addr);
			buf.append("\n<text>");
			SpecXmlUtils.xmlEscape(buf, text);
			buf.append("</text>\n");
			buf.append("</comment>\n");

		}
	}

	/**
	 * Generate XML for comments of a certain type
	 * 
	 * @param addrset = addresses over which to search for comments
	 * @param buf = StringBuilder where XML should be written
	 * @param commenttype = type of comment
	 */
	private void generateCommentXML(AddressSetView addrset, Address addr, StringBuilder buf,
			int commenttype) {
		String typename;
		switch (commenttype) {
			case CodeUnit.EOL_COMMENT:
				typename = "user1";
				break;
			case CodeUnit.PRE_COMMENT:
				typename = "user2";
				break;
			case CodeUnit.POST_COMMENT:
				typename = "user3";
				break;
			case CodeUnit.PLATE_COMMENT:
				typename = "header";
				break;
			default:
				typename = "";
				break;
		}
		AddressIterator iter = listing.getCommentAddressIterator(commenttype, addrset, true);
		while (iter.hasNext()) {
			Address commaddr = iter.next();
			String text = listing.getComment(commenttype, commaddr);
			if (text != null) {
				if (commenttype == CodeUnit.PLATE_COMMENT) {
					// Plate comments on the function entry
					// address are considered part of the header
					if (commaddr.equals(addr)) {
						continue;
					}
				}

				buf.append("<comment");
				SpecXmlUtils.encodeStringAttribute(buf, "type", typename);
				buf.append(">\n");
				AddressXML.buildXML(buf, addr);
				AddressXML.buildXML(buf, commaddr);
				buf.append("\n<text>");
				SpecXmlUtils.xmlEscape(buf, text);
				buf.append("</text>\n");
				buf.append("</comment>\n");
			}
		}

	}

	/**
	 * Called by the native decompiler to query the GHIDRA database about any
	 * symbols at the given address.
	 * 
	 * @param addrstring XML encoded address to query
	 * @return XML encoded result. Either function, reference, datatype, or hole
	 */
	public String getMappedSymbolsXML(String addrstring) { // Return XML describing data or functions at addr
		Address addr;
		try {
			addr = AddressXML.readXML(addrstring, addrfactory);
			if (overlaySpace != null) {
				addr = overlaySpace.getOverlayAddress(addr);
			}
			if (addr == Address.NO_ADDRESS) {
				// Unknown spaces may result from "spacebase" registers defined in cspec
				return null;
			}
		}
		catch (PcodeXMLException e) {
			Msg.error(this, "Decompiling " + funcEntry + ": " + e.getMessage());
			return null;
		}
		try {
			String res = null;
			Object obj = lookupSymbol(addr);
			if (obj instanceof Function) {
				boolean includeDefaults = addr.equals(funcEntry);
				res = buildFunctionXML((Function) obj, addr, includeDefaults);
			}
			else if (obj instanceof Data) {
				res = buildData((Data) obj);
			}
			else if (obj instanceof ExternalReference) {
				res = buildExternalRef(addr, (ExternalReference) obj);
			}
			else if (obj instanceof Symbol) {
				res = buildLabel((Symbol) obj, addr);
			}
			if (res == null) { // There is a hole, describe the extent of the hole
				res = buildHole(addr).toString();
			}

			return res;
		}
		catch (Exception e) {
			Msg.error(this, "Decompiling " + funcEntry + ", mapped symbol error for " + addrstring +
				": " + e.getMessage(), e);
		}
		return null;
	}

	public String getExternalRefXML(String addrstring) { // Return any external reference at addr
		Address addr;
		try {
			addr = AddressXML.readXML(addrstring, addrfactory);
			if (overlaySpace != null) {
				addr = overlaySpace.getOverlayAddress(addr);
			}
		}
		catch (PcodeXMLException e) {
			Msg.error(this, "Decompiling " + funcEntry + ": " + e.getMessage());
			return null;
		}
		try {

			Function func = null;
			if (cachedFunction != null && cachedFunction.getEntryPoint().equals(addr)) {
				func = cachedFunction;
			}
			else {
				ExternalReference extRef = getExternalReference(addr);
				if (extRef != null) {
					func = listing.getFunctionAt(extRef.getToAddress());
					if (func == null) {
						Symbol symbol = extRef.getExternalLocation().getSymbol();
						long extId;
						if (symbol != null) {
							extId = symbol.getID();
						}
						else {
							extId = program.getSymbolTable().getDynamicSymbolID(addr);

						}
						HighSymbol shellSymbol =
							new HighFunctionShellSymbol(extId, extRef.getLabel(), addr, dtmanage);
						return buildResult(shellSymbol, null);
					}
				}
				else {
					func = listing.getFunctionAt(addr);
				}
			}
			if (func == null) {
				// Its conceivable we could have external data, but we aren't currently checking for it
				return null;
			}

			HighFunction hfunc = new HighFunction(func, pcodelanguage, pcodecompilerspec, dtmanage);

			int extrapop = getExtraPopOverride(func, addr);
			hfunc.grabFromFunction(extrapop, false, (extrapop != default_extrapop));

			HighSymbol funcSymbol = new HighFunctionSymbol(addr, 2, hfunc);
			Namespace namespc = funcSymbol.getNamespace();
			if (debug != null) {
				debug.getFNTypes(hfunc);
				debug.addPossiblePrototypeExtension(func);
			}
			return buildResult(funcSymbol, namespc);
		}
		catch (Exception e) {
			Msg.error(this,
				"Decompiling " + funcEntry + ", error in getExternalRefXML: " + e.getMessage(), e);
		}
		return null;
	}

	public String getType(String name, String idstr) {
		DataType type = dtmanage.findBaseType(name, idstr);
		if (type == null) {
			return null;
		}
		StringBuilder resBuf = new StringBuilder();
		dtmanage.buildType(resBuf, type, 0);
		resBuf.append("\n"); // Make into official XML document
		String res = resBuf.toString();
		if (debug != null) {
			debug.getType(type);
		}
		return res;
	}

	public String getRegister(String name) {
		Register reg = pcodelanguage.getRegister(name);
		if (reg == null) {
			throw new RuntimeException("No Register Defined: " + name);
		}
		StringBuilder resBuf = buildRegister(reg);
		resBuf.append("\n");
		return resBuf.toString();
	}

	public String getRegisterName(String addrstring) {
		try {

			Address addr = AddressXML.readXML(addrstring, addrfactory);
			int size = AddressXML.readXMLSize(addrstring);
			Register reg = pcodelanguage.getRegister(addr, size);
			if (reg == null) {
				return null;
			}
			return reg.getName();
		}
		catch (PcodeXMLException e) {
			Msg.error(this, "Decompiling " + funcEntry +
				", error while searching for register name: " + e.getMessage(), e);
		}
		return null;
	}

	public String getTrackedRegisters(String addrstring) {
		Address addr;
		try {
			addr = AddressXML.readXML(addrstring, addrfactory);
			if (overlaySpace != null) {
				addr = overlaySpace.getOverlayAddress(addr);
			}
		}
		catch (PcodeXMLException e) {
			Msg.error(this, "Decompiling " + funcEntry + ": " + e.getMessage());
			return null;
		}
		ProgramContext context = program.getProgramContext();

		StringBuilder stringBuf = new StringBuilder();

		stringBuf.append("<tracked_pointset");
		AddressXML.appendAttributes(stringBuf, addr);
		stringBuf.append(">\n");
		for (Register reg : context.getRegisters()) {
			if (reg.isProcessorContext()) {
				continue;
			}
			BigInteger val = context.getValue(reg, addr, false);
			if (val != null) {
				buildTrackSet(stringBuf, reg, val.longValue());
			}
		}
		stringBuf.append("</tracked_pointset>\n");
		String res = stringBuf.toString();
		if (debug != null) {
			debug.getTrackedRegisters(res);
		}
		return res;
	}

	public String getUserOpName(String indexStr) {
		int index = Integer.parseInt(indexStr);
		String name = pcodelanguage.getUserDefinedOpName(index);
		return name;
	}

	private String buildResult(HighSymbol highSymbol, Namespace namespc) {
		long namespaceId;
		if (namespc == null || namespc instanceof Library) {
			namespaceId = Namespace.GLOBAL_NAMESPACE_ID;
		}
		else {
			namespaceId = namespc.getID();
		}
		StringBuilder res = new StringBuilder();
		res.append("<result");
		SpecXmlUtils.encodeUnsignedIntegerAttribute(res, "id", namespaceId);
		res.append(">\n");
		if (debug != null) {
			StringBuilder res2 = new StringBuilder();
			HighSymbol.buildMapSymXML(res2, highSymbol);
			String res2string = res2.toString();
			debug.getMapped(namespc, res2string);
			res.append(res2string);
		}
		else {
			HighSymbol.buildMapSymXML(res, highSymbol);
		}
		res.append("</result>\n");

		return res.toString();
	}

	private String buildData(Data data) { // Convert global variable to XML
		Symbol sym = data.getPrimarySymbol();
		HighCodeSymbol highSymbol;
		if (sym != null) {
			highSymbol = new HighCodeSymbol(sym.getID(), sym.getName(), data, dtmanage);
		}
		else {
			highSymbol = new HighCodeSymbol(0,
				SymbolUtilities.getDynamicName(program, data.getAddress()), data, dtmanage);
			SymbolEntry entry = highSymbol.getFirstWholeMap();
			if (data.getDataType() == DataType.DEFAULT && !entry.isReadOnly() &&
				!entry.isVolatile()) {
				return null;
			}
		}
		if (debug != null) {
			debug.getType(highSymbol.getDataType());
		}
		Namespace namespc = (sym != null) ? sym.getParentNamespace() : null;
		return buildResult(highSymbol, namespc);
	}

	private StringBuilder buildRegister(Register reg) {
		StringBuilder resBuf = new StringBuilder();
		resBuf.append("<addr");
		SpecXmlUtils.encodeStringAttribute(resBuf, "space", reg.getAddressSpace().getName());
		SpecXmlUtils.encodeUnsignedIntegerAttribute(resBuf, "offset", reg.getOffset());
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", reg.getMinimumByteSize());
		resBuf.append("/>");
		return resBuf;
	}

	/**
	 * Generate description of a non-data symbol, probably a code label
	 * 
	 * @param sym is the symbol
	 * @return the XML description
	 */
	private String buildLabel(Symbol sym, Address addr) {
		HighSymbol labelSymbol = new HighLabelSymbol(sym.getName(), addr, dtmanage);
		Namespace namespc = sym.getParentNamespace();
		return buildResult(labelSymbol, namespc);
	}

	/**
	 * Check address is read only. This only checks whether the block containing
	 * the address is read-only. It does not, and should not, check if there is
	 * a data object that has been set to constant
	 * 
	 * @param addr - address to check
	 * 
	 * @return true if the block is read_only, and there are no write
	 *         references.
	 */
	private boolean isReadOnlyNoData(Address addr) {
		boolean readonly = false;
		MemoryBlock block = program.getMemory().getBlock(addr);
		if (block != null) {
			readonly = !block.isWrite();
			// if the block says read-only, check the refs to the variable
			// if the block says read-only, check the refs to the variable
			if (readonly) {
				ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(addr);
				int count = 0;
//				boolean foundRead = false;
				while (refIter.hasNext() && count < 100) {
					Reference ref = refIter.next();
					if (ref.getReferenceType().isWrite()) {
						readonly = false;
						break;
					}
					if (ref.getReferenceType().isRead()) {
//						foundRead = true;
					}
					count++;
				}
				// TODO: Don't do override if no read reference found
				//
				// if we only have indirect refs to it, don't assume readonly!
				//if (!foundRead && readonly && count > 1) {
				//	readonly = false;
				//}
				// they must be reading it multiple times for some reason
				// if (readonly && count > 1) {
				// 	readonly = false;
				// }
			}
		}
		return readonly;
	}

	/**
	 * This function deals with the vagaries of the getMappedSymbolsXML
	 * interface when the queried address is in the body of a function.
	 * Basically, if the address is the entry point of the function, all the
	 * function data is sent. Otherwise a hole is sent back of the biggest
	 * contiguous block in the body of the function containing the queried
	 * address
	 * 
	 * @param func Function whose body contains the address
	 * @param addr The queried address
	 * @param includeDefaultNames true if default parameter names should be
	 *            included
	 * @return XML string describing the function or the hole
	 */
	private String buildFunctionXML(Function func, Address addr, boolean includeDefaultNames) {
		Address entry = func.getEntryPoint();
		if (entry.getAddressSpace().equals(addr.getAddressSpace())) {
			long diff = addr.getOffset() - entry.getOffset();
			if ((diff >= 0) && (diff < 8)) {
				HighFunction hfunc =
					new HighFunction(func, pcodelanguage, pcodecompilerspec, dtmanage);

				int extrapop = getExtraPopOverride(func, addr);
				hfunc.grabFromFunction(extrapop, includeDefaultNames,
					(extrapop != default_extrapop));

				HighSymbol functionSymbol = new HighFunctionSymbol(entry, (int) (diff + 1), hfunc);
				Namespace namespc = functionSymbol.getNamespace();
				if (debug != null) {
					debug.getFNTypes(hfunc);
					debug.addPossiblePrototypeExtension(func);
				}
				return buildResult(functionSymbol, namespc);
			}
		}

		AddressRangeIterator iter = func.getBody().getAddressRanges();
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			if (range.contains(addr)) {
				Address first = range.getMinAddress();
				Address last = range.getMaxAddress();
				boolean readonly = true; // Treat function body as readonly
				return buildHoleXML(first.getAddressSpace().getPhysicalSpace().getName(),
					first.getUnsignedOffset(), last.getUnsignedOffset(), readonly, false);
			}
		}
		// There is probably some sort of error, just return a block
		// containing the single queried address
		return buildHoleXML(addr.getAddressSpace().getPhysicalSpace().getName(),
			addr.getUnsignedOffset(), addr.getUnsignedOffset(), true, false);
	}

	private int getExtraPopOverride(Function func, Address addr) {
		if (func.getEntryPoint().equals(funcEntry)) {
			// getting the purge for the function being decompiled
			return default_extrapop;
		}

		int extrapop = default_extrapop;

		// figure out if this function we are decompiling overrides the stack depth
		// change for this function
		Function containedFunc = getFunctionAt(funcEntry);
		if (containedFunc == null) {
			return extrapop;
		}
		AddressIterator iter = CallDepthChangeInfo.getStackDepthChanges(containedFunc.getProgram(),
			containedFunc.getBody());
		while (iter.hasNext()) {
			Address changeAddr = iter.next();
			Reference refs[] =
				func.getProgram().getReferenceManager().getFlowReferencesFrom(changeAddr);
			for (Reference element : refs) {
				if (element.getToAddress().equals(addr)) {
					Integer change =
						CallDepthChangeInfo.getStackDepthChange(func.getProgram(), changeAddr);
					if (change != null) {
						extrapop = change;
					}
				}
			}
		}
		return extrapop;
	}

	private String buildHoleXML(String nm, long first, long last, boolean readonly,
			boolean isVolatile) {
		StringBuilder resBuf = new StringBuilder();
		resBuf.append("<hole");
		SpecXmlUtils.encodeBooleanAttribute(resBuf, "readonly", readonly);
		SpecXmlUtils.encodeBooleanAttribute(resBuf, "volatile", isVolatile);
		SpecXmlUtils.encodeStringAttribute(resBuf, "space", nm);
		SpecXmlUtils.encodeUnsignedIntegerAttribute(resBuf, "first", first);
		SpecXmlUtils.encodeUnsignedIntegerAttribute(resBuf, "last", last);
		resBuf.append("/>\n");
		return resBuf.toString();
	}

	/**
	 * Calculate the beginning and ending address of the biggest region around
	 * addr that does not contain any symbol.
	 * 
	 * This was not working correctly and it is too difficult to find the
	 * biggest region for which there is no codeunit, and where the volatile and
	 * readonly properties don't vary
	 * 
	 * So now we assume that biggest hole we can find is just 1 byte
	 * 
	 * @param addr = Address around which to find region
	 * @return String <hole> tag
	 */
	private String buildHole(Address addr) {
//		AddressSpace addrspace = addr.getAddressSpace();
//		Address before,after;
//		MemoryBlock block = program.getMemory().getBlock(addr);
//		boolean readonly;
//		boolean isVolatile = isVolatileNoData(addr);
//		if (block != null) {
//			before = block.getStart();
//			after = block.getEnd();
//			readonly = !block.isWrite();
//		}
//		else {
//			before = addrspace.getAddress(0);
//			after = addrspace.getMaxAddress();
//			readonly = false;
//		}
//		CodeUnit cubefore = listing.getDefinedCodeUnitBefore(addr);
//		if (cubefore != null) {
//			Address tmp = cubefore.getMaxAddress();
//			if (tmp.getAddressSpace().getBaseSpaceID()==addrspace.getBaseSpaceID()) {
//				tmp = tmp.add(1);
//				if (tmp.getOffset()<=addr.getOffset()) {
//					if (tmp.getOffset() > before.getOffset())
//						before = tmp;
//				}
//				else {  // Address is inside codeunit
//					tmp = cubefore.getMaxAddress();
//					if (tmp.getOffset()<after.getOffset())
//						after = tmp;
//					tmp = cubefore.getMinAddress();
//					if (tmp.getOffset() > before.getOffset())
//						before = tmp;
//				}
//			}
//		}
//		CodeUnit cuafter = listing.getDefinedCodeUnitAfter(addr);
//		if (cuafter != null) {
//			Address tmp = cuafter.getMinAddress();
//			if ((tmp.getAddressSpace()==addrspace)) {
//				tmp = tmp.subtract(1);
//				if (tmp.getOffset()<after.getOffset()) {
//					after = tmp;
//				}
//			}
//		}
//		return buildHoleXML(addrspace.getPhysicalSpace().getName(),before.getOffset(),
//						after.getOffset(),readonly,isVolatile);
		boolean readonly = isReadOnlyNoData(addr);
		boolean isvolatile = isVolatileNoData(addr);
		return buildHoleXML(addr.getAddressSpace().getPhysicalSpace().getName(),
			addr.getUnsignedOffset(), addr.getUnsignedOffset(), readonly, isvolatile);
	}

	private String buildExternalRef(Address addr, ExternalReference ref) {
		// The decompiler model was to assume that the ExternalReference
		// object could resolve the physical address where the dll
		// function was getting loaded, just as a linker would do.
		// GHIDRA may not be able to do full linking so it maintains a special
		// External address (in an External AddressSpace) as a level
		// of indirection for letting the user map the dll themselves.
		// The ref.getExternalAddress() is this special address, which
		// is NOT a physical address. Right now the decompiler doesn't
		// care where the external function is mapped to, but it does
		// want a physical address which is unique.  So we currently use
		// the address of the reference to hang the function on, and make
		// no attempt to get a realistic linked address.  This works because
		// we never read bytes or look up code units at the address.
		HighSymbol externSymbol = new HighExternalSymbol(ref.getLabel(), addr, addr, dtmanage);
		return buildResult(externSymbol, null);
	}

	private void buildTrackSet(StringBuilder buf, Register reg, long val) {
		AddressSpace spc = reg.getAddressSpace();
		long offset = reg.getOffset();
		int size = reg.getMinimumByteSize();
		buf.append("<set");
		SpecXmlUtils.encodeStringAttribute(buf, "space", spc.getName());
		SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "offset", offset);
		SpecXmlUtils.encodeSignedIntegerAttribute(buf, "size", size);
		SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "val", val);
		buf.append("/>\n");
	}

	private ExternalReference getExternalReference(Address addr) {
		Data data = listing.getDefinedDataAt(addr);
		if (data != null && data.isPointer()) {
			Reference ref = data.getPrimaryReference(0);
			if (ref instanceof ExternalReference) {
				return (ExternalReference) ref;
			}
		}
		return null;
	}

	/**
	 * Return the global object being referred to by addr
	 * 
	 * @param addr = Address being queried
	 * @return the global object
	 */
	private Object lookupSymbol(Address addr) {
		ExternalReference ref = getExternalReference(addr);
		if (ref != null) {
			return ref;
		}
		Function func = getFunctionContaining(addr);
		if (func != null) {
			return func;
		}
		Register reg = program.getRegister(addr);
		if (reg != null) {
			// This isn't an actual symbol, let decompiler fill in the register name at a later time
			return null;
		}
		Data data = listing.getDataContaining(addr);
		if (data != null) {
			return data;
		}
		// This final query checks for labels with no real datatype attached
		// which works especially for labels for addresses without a memory block 
		Symbol sym = program.getSymbolTable().getPrimarySymbol(addr);
		if ((sym != null) && sym.isGlobal()) {
			return sym; // A label of global data of some sort
		}
		return null;
	}

	/**
	 * Check whether the address is volatile. Do not check the data object.
	 * 
	 * @param addr is address to check for volatility
	 * @return true if the address is volatile
	 */
	private boolean isVolatileNoData(Address addr) {
		if (program.getLanguage().isVolatile(addr)) {
			return true;
		}
		MemoryBlock block = program.getMemory().getBlock(addr);
		return (block != null && block.isVolatile());
	}

	private Function getFunctionContaining(Address addr) {
		if (cachedFunction != null && cachedFunction.getBody().contains(addr)) {
			return cachedFunction;
		}
		return listing.getFunctionContaining(addr);
	}

	private Function getFunctionAt(Address addr) {
		if (cachedFunction != null && cachedFunction.getEntryPoint().equals(addr)) {
			return cachedFunction;
		}
		ExternalReference extRef = getExternalReference(addr);
		if (extRef != null) {
			return listing.getFunctionAt(extRef.getToAddress());
		}
		return listing.getFunctionAt(addr);
	}

	/**
	 * Return true if there are no "replacement" characters in the string
	 * @param string is the string to test
	 * @return true if no replacements
	 */
	private boolean isValidChars(String string) {
		char replaceChar = '\ufffd';
		for (int i = 0; i < string.length(); ++i) {
			char c = string.charAt(i);
			if (c == replaceChar) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Check for a string at an address and return a UTF8 encoded byte array.
	 * If there is already data present at the address, use this to determine the
	 * string encoding. Otherwise use the data-type info passed in to determine the encoding.
	 * Check that the bytes at the address represent a valid string encoding that doesn't
	 * exceed the maximum character limit passed in.  Return null if the string is invalid.
	 * Return the string translated into a UTF8 byte array otherwise.  A (valid) empty
	 * string is returned as a zero length array.
	 * @param addrString is the XML encoded address and maximum byte limit
	 * @param dtName is the name of a character data-type
	 * @param dtId is the id associated with the character data-type
	 * @return the UTF8 encoded byte array or null
	 */
	public StringData getStringData(String addrString, String dtName, String dtId) {
		Address addr;
		int maxChars;
		try {
			addr = AddressXML.readXML(addrString, addrfactory);
			maxChars = AddressXML.readXMLSize(addrString);
			if (overlaySpace != null) {
				addr = overlaySpace.getOverlayAddress(addr);
			}
			if (addr == Address.NO_ADDRESS) {
				throw new PcodeXMLException("Address does not physically map");
			}
		}
		catch (PcodeXMLException e) {
			Msg.error(this, "Decompiling " + funcEntry + ": " + e.getMessage());
			return null;
		}
		Data data = program.getListing().getDataContaining(addr);
		Settings settings = SettingsImpl.NO_SETTINGS;
		AbstractStringDataType dataType = null;
		StringDataInstance stringInstance = null;
		int length = 0;
		if (data != null) {
			if (data.getDataType() instanceof AbstractStringDataType) {
				// There is already a string here.  Use its configuration to
				// set up the StringDataInstance
				settings = data;
				dataType = (AbstractStringDataType) data.getDataType();
				length = data.getLength();
				if (length <= 0) {
					return null;
				}
				long diff = addr.subtract(data.getAddress()) *
					addr.getAddressSpace().getAddressableUnitSize();
				if (diff < 0 || diff >= length) {
					return null;
				}
				length -= diff;
				MemoryBufferImpl buf = new MemoryBufferImpl(program.getMemory(), addr, 64);
				stringInstance = dataType.getStringDataInstance(buf, settings, length);
			}
		}
		if (stringInstance == null) {
			// There is no string and/or something else at the address.
			// Setup StringDataInstance based on raw memory
			DataType dt = dtmanage.findBaseType(dtName, dtId);
			if (dt instanceof AbstractStringDataType) {
				dataType = (AbstractStringDataType) dt;
			}
			else {
				if (dt != null) {
					int size = dt.getLength();
					if (size == 2) {
						dataType = TerminatedUnicodeDataType.dataType;
					}
					else if (size == 4) {
						dataType = TerminatedUnicode32DataType.dataType;
					}
					else {
						dataType = TerminatedStringDataType.dataType;
					}
				}
				else {
					dataType = TerminatedStringDataType.dataType;
				}
			}
			MemoryBufferImpl buf = new MemoryBufferImpl(program.getMemory(), addr, 64);
			stringInstance = dataType.getStringDataInstance(buf, settings, maxChars);
			length = stringInstance.getStringLength();
			if (length < 0 || length > maxChars) {
				return null;
			}
		}
		String stringVal;
		if (stringInstance.isShowTranslation() && stringInstance.getTranslatedValue() != null) {
			stringVal = stringInstance.getTranslatedValue();
		}
		else {
			stringVal = stringInstance.getStringValue();
		}

		if (!isValidChars(stringVal)) {
			return null;
		}
		StringData stringData = new StringData();
		stringData.isTruncated = false;
		if (stringVal.length() > maxChars) {
			stringData.isTruncated = true;
			stringVal = stringVal.substring(0, maxChars);
		}
		stringData.byteData = stringVal.getBytes(utf8Charset);
		if (debug != null) {
			debug.getStringData(addr, stringData);
		}
		return stringData;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class NameListHandler extends DefaultHandler {
		private ArrayList<String> res;
		private StringBuilder curbuffer;

		NameListHandler() {
			super();
			res = new ArrayList<>();
			curbuffer = null;
		}

		@Override
		public void startElement(String uri, String localName, String rawName, Attributes attr)
				throws SAXException {
			if (localName.equals("val")) {
				curbuffer = new StringBuilder();
			}
		}

		@Override
		public void characters(char[] arg0, int arg1, int arg2) throws SAXException {
			if ((curbuffer != null) && (arg0 != null)) {
				curbuffer.append(arg0, arg1, arg2);
			}
		}

		@Override
		public void endElement(String arg0, String arg1, String arg2) throws SAXException {
			if (arg1.equals("val")) {
				res.add(curbuffer.toString());
				curbuffer = null;
			}
		}

		public ArrayList<String> getList() {
			return res;
		}
	}
}
