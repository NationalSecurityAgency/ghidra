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

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import ghidra.app.cmd.function.CallDepthChangeInfo;
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

		public StringData(String stringVal, int maxChars) {
			this.isTruncated = false;
			if (stringVal.length() > maxChars) {
				this.isTruncated = true;
				stringVal = stringVal.substring(0, maxChars);
			}
			this.byteData = stringVal.getBytes(StandardCharsets.UTF_8);
		}
	}

	private DecompileDebug debug;
	private Program program;
	private Listing listing;
	private Function cachedFunction;
	private AddressSet undefinedBody;
	private Address funcEntry;
	private int default_extrapop;
	private Language pcodelanguage;
	private CompilerSpec pcodecompilerspec;
	private AddressFactory addrfactory;
	private ConstantPool cpool;
	private PcodeDataTypeManager dtmanage;
	private String nativeMessage;

	private InstructionBlock lastPseudoInstructionBlock;
	private Disassembler pseudoDisassembler;

	public DecompileCallback(Program prog, Language language, CompilerSpec compilerSpec,
			PcodeDataTypeManager dt) {
		program = prog;
		pcodelanguage = language;
		pcodecompilerspec = compilerSpec;
		listing = program.getListing();
		addrfactory = program.getAddressFactory();
		dtmanage = dt;
		default_extrapop = pcodecompilerspec.getDefaultCallingConvention().getExtrapop();
		cpool = null;
		nativeMessage = null;
		debug = null;
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
		debug = dbg;
		if (debug != null) {
			debug.setPcodeDataTypeManager(dtmanage);
		}
		nativeMessage = null; // Clear last message
		lastPseudoInstructionBlock = null;
		if (pseudoDisassembler != null) {
			pseudoDisassembler.resetDisassemblerContext();
		}
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

	/**
	 * Get bytes from the program's memory image.
	 * @param addr is the starting address to fetch bytes from
	 * @param size is the number of bytes to fetch
	 * @return the bytes matching the query or null if the query can't be met
	 */
	public byte[] getBytes(Address addr, int size) {
		if (addr == Address.NO_ADDRESS) {
			Msg.error(this, "Address does not physically map");
			return null;
		}
		if (addr.isRegisterAddress()) {
			return null;
		}
		try {
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
		catch (Exception e) {
			Msg.error(this,
				"Decompiling " + funcEntry + ", error while accessing bytes: " + e.getMessage(), e);
		}
		return null;
	}

	/**
	 * Collect any/all comments for the function starting at the indicated
	 * address.  Filter based on selected comment types.
	 * 
	 * @param addr is the indicated address
	 * @param types is the set of flags
	 * @param resultEncoder will contain the collected comments
	 * @throws IOException for errors in the underlying stream
	 */
	public void getComments(Address addr, int types, Encoder resultEncoder) throws IOException {
		Function func = getFunctionAt(addr);
		if (func == null) {
			return;
		}
		encodeComments(resultEncoder, addr, func, types);
		if (debug != null) {
			XmlEncode xmlEncode = new XmlEncode();
			encodeComments(xmlEncode, addr, func, types);
			debug.getComments(xmlEncode.toString());
		}
	}

	/**
	 * Generate p-code ops for the instruction at the given address
	 * @param addr is the given address
	 * @param resultEncoder will contain the generated p-code ops
	 */
	public void getPcode(Address addr, PackedEncode resultEncoder) {
		try {
			Instruction instr = getInstruction(addr);
			if (instr == null) {
				return;
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

			instr.getPrototype()
					.getPcodePacked(resultEncoder, instr.getInstructionContext(),
						new InstructionPcodeOverride(instr));
			return;
		}
		catch (UsrException e) {
			Msg.warn(this,
				"Decompiling " + funcEntry + ", pcode error at " + addr + ": " + e.getMessage());
		}
		catch (Exception e) {
			Msg.error(this,
				"Decompiling " + funcEntry + ", pcode error at " + addr + ": " + e.getMessage(), e);
		}
		resultEncoder.clear();
	}

	/**
	 * Encode a list of pcode, representing an entire Instruction, to the stream
	 * 
	 * @param encoder is the stream encoder
	 * @param addr is the Address to associate with the Instruction
	 * @param ops is the pcode ops
	 * @param fallthruoffset number of bytes after instruction start that pcode
	 *            flow falls into
	 * @param paramshift special instructions for injection use
	 * @param addrFactory is the address factory for recovering address space names
	 * @throws IOException for errors in the underlying stream
	 */
	public static void encodeInstruction(Encoder encoder, Address addr, PcodeOp[] ops,
			int fallthruoffset, int paramshift, AddressFactory addrFactory) throws IOException {
		if ((ops.length == 1) && (ops[0].getOpcode() == PcodeOp.UNIMPLEMENTED)) {
			encoder.openElement(ELEM_UNIMPL);
			encoder.writeSignedInteger(ATTRIB_OFFSET, fallthruoffset);
			encoder.closeElement(ELEM_UNIMPL);
			return;
		}
		encoder.openElement(ELEM_INST);
		encoder.writeSignedInteger(ATTRIB_OFFSET, fallthruoffset);
		if (paramshift != 0) {
			encoder.writeSignedInteger(ATTRIB_PARAMSHIFT, paramshift);
		}
		AddressXML.encode(encoder, addr);
		for (PcodeOp op : ops) {
			op.encodeRaw(encoder, addrFactory);
		}
		encoder.closeElement(ELEM_INST);
	}

	/**
	 * Generate p-code ops for a named injection payload
	 * @param nm is the name of the payload
	 * @param paramDecoder contains the context
	 * @param type is the type of payload
	 * @param resultEncoder will contain the generated p-code ops
	 */
	public void getPcodeInject(String nm, Decoder paramDecoder, int type, Encoder resultEncoder) {
		PcodeInjectLibrary snippetLibrary = pcodecompilerspec.getPcodeInjectLibrary();

		InjectPayload payload = snippetLibrary.getPayload(type, nm);
		if (payload == null) {
			Msg.warn(this, "Decompiling " + funcEntry + ", no pcode inject with name: " + nm);
			return;		// No fixup associated with this name
		}
		InjectContext con = snippetLibrary.buildInjectContext();
		PcodeOp[] pcode;
		try {
			con.decode(paramDecoder);
		}
		catch (DecoderException e) {
			Msg.error(this, "Decompiling " + funcEntry + ": " + e.getMessage());
			return;
		}
		try {
			int fallThruOffset;
			if (payload.getType() == InjectPayload.EXECUTABLEPCODE_TYPE) {
				// Executable p-code has no underlying instruction address and
				// does (should) not use the inst_start, inst_next symbols that need
				// to know about it.
				fallThruOffset = 4;		// Provide a dummy length
			}
			else {
				Instruction instr = getInstruction(con.baseAddr);
				if (instr == null) {
					Msg.warn(this, "Decompiling " + funcEntry + ", pcode inject error at " +
						con.baseAddr + ": instruction not found");
					return;
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
				return;		// Return without result, which should let the decompiler exit gracefully
			}
			encodeInstruction(resultEncoder, con.baseAddr, pcode, fallThruOffset,
				payload.getParamShift(), addrfactory);
			if (debug != null) {
				XmlEncode xmlEncode = new XmlEncode();
				encodeInstruction(xmlEncode, con.baseAddr, pcode, fallThruOffset,
					payload.getParamShift(), addrfactory);
				debug.addInject(con.baseAddr, nm, type, xmlEncode.toString());
			}
		}
		catch (UnknownInstructionException e) {
			Msg.warn(this, "Decompiling " + funcEntry + ", pcode inject error at " + con.baseAddr +
				": " + e.getMessage());
		}
		catch (Exception e) {
			Msg.error(this, "Decompiling " + funcEntry + ", pcode inject error at " + con.baseAddr +
				": " + e.getMessage(), e);
		}
	}

	/**
	 * Look up details of a specific constant pool reference
	 * @param refs is the constant id (which may consist of multiple integers)
	 * @param resultEncoder will contain the reference details
	 * @throws IOException for errors in the underlying stream while encoding results
	 */
	public void getCPoolRef(long[] refs, Encoder resultEncoder) throws IOException {
		if (cpool == null) {
			cpool = pcodecompilerspec.getPcodeInjectLibrary().getConstantPool(program);
		}
		Record record = cpool.getRecord(refs);
		record.encode(resultEncoder, refs[0], dtmanage);
		if (debug != null) {
			XmlEncode xmlEncode = new XmlEncode();
			record.encode(xmlEncode, refs[0], dtmanage);
			debug.getCPoolRef(xmlEncode.toString(), refs);
		}
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
			if (program.getMemory().isExternalBlockAddress(addr)) {
				throw new UnknownInstructionException(
					"Unable to disassemble EXTERNAL block location: " + addr);
			}
		}
		throw new UnknownInstructionException("Invalid instruction address (improperly aligned)");
	}

	/**
	 * Return the first symbol name at the given address
	 * @param addr is the given address
	 * @return the symbol or null if no symbol is found
	 */
	public String getCodeLabel(Address addr) {
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
	 * Write a description of the formal namespace path to the given namespace
	 * @param id is the ID of the given namespace
	 * @param resultEncoder is where to write the encoded result
	 * @throws IOException for errors in the underlying stream
	 */
	public void getNamespacePath(long id, Encoder resultEncoder) throws IOException {
		Namespace namespace = getNameSpaceByID(id);
		HighFunction.encodeNamespace(resultEncoder, namespace);
		if (debug != null) {
			debug.getNamespacePath(namespace);
		}
	}

	private void encodeHeaderComment(Encoder encoder, Function func) throws IOException {
		Address addr = func.getEntryPoint();
		String text = listing.getComment(CodeUnit.PLATE_COMMENT, addr);
		if (text != null) {
			encoder.openElement(ELEM_COMMENT);
			encoder.writeString(ATTRIB_TYPE, "header");
			AddressXML.encode(encoder, addr);
			AddressXML.encode(encoder, addr);
			encoder.openElement(ELEM_TEXT);
			encoder.writeString(ATTRIB_CONTENT, text);
			encoder.closeElement(ELEM_TEXT);
			encoder.closeElement(ELEM_COMMENT);
		}
	}

	/**
	 * Encode comments of a specific type to stream for a given address set.  Comments are
	 * collected from the listing.  The encoding associates the comment both with the address where
	 * it was placed, but also with the (entry point) address of the function containing it.
	 * Plate comments whose address matches the function entry point are not encoded.
	 * 
	 * @param encoder is the stream encoder
	 * @param addrset is the address set over which to search
	 * @param addr is the entry point of the function
	 * @param commenttype is the type of comment
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeCommentsType(Encoder encoder, AddressSetView addrset, Address addr,
			int commenttype) throws IOException {
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
				encoder.openElement(ELEM_COMMENT);
				encoder.writeString(ATTRIB_TYPE, typename);
				AddressXML.encode(encoder, addr);
				AddressXML.encode(encoder, commaddr);
				encoder.openElement(ELEM_TEXT);
				encoder.writeString(ATTRIB_CONTENT, text);
				encoder.closeElement(ELEM_TEXT);
				encoder.closeElement(ELEM_COMMENT);
			}
		}

	}

	private void encodeComments(Encoder encoder, Address addr, Function func, int flags)
			throws IOException {
		AddressSetView addrset = func.getBody();
		encoder.openElement(ELEM_COMMENTDB);
		if ((flags & 8) != 0) {
			encodeHeaderComment(encoder, func);
		}
		if ((flags & 1) != 0) {
			encodeCommentsType(encoder, addrset, addr, CodeUnit.EOL_COMMENT);
		}
		if ((flags & 2) != 0) {
			encodeCommentsType(encoder, addrset, addr, CodeUnit.PRE_COMMENT);
		}
		if ((flags & 4) != 0) {
			encodeCommentsType(encoder, addrset, addr, CodeUnit.POST_COMMENT);
		}
		if ((flags & 8) != 0) {
			encodeCommentsType(encoder, addrset, addr, CodeUnit.PLATE_COMMENT);
		}
		encoder.closeElement(ELEM_COMMENTDB);
	}

	/**
	 * Describe data or functions at the given address; either function, reference, data, or hole.
	 * Called by the native decompiler to query the GHIDRA database about any
	 * symbols at the given address.
	 * 
	 * @param addr is the given address
	 * @param resultEncoder is where to write encoded description
	 */
	public void getMappedSymbols(Address addr, Encoder resultEncoder) {
		if (addr == Address.NO_ADDRESS) {
			// Unknown spaces may result from "spacebase" registers defined in cspec
			return;
		}
		try {
			Object obj = lookupSymbol(addr);
			if (obj instanceof Function) {
				boolean includeDefaults = addr.equals(funcEntry);
				encodeFunction(resultEncoder, (Function) obj, addr, includeDefaults);
			}
			else if (obj instanceof Data) {
				if (!encodeData(resultEncoder, (Data) obj)) {
					encodeHole(resultEncoder, addr);
				}
			}
			else if (obj instanceof ExternalReference) {
				encodeExternalRef(resultEncoder, addr, (ExternalReference) obj);
			}
			else if (obj instanceof Symbol) {
				encodeLabel(resultEncoder, (Symbol) obj, addr);
			}
			else {
				encodeHole(resultEncoder, addr);	// There is a hole, describe the extent of the hole
			}

			return;
		}
		catch (Exception e) {
			Msg.error(this, "Decompiling " + funcEntry + ", mapped symbol error for " + addr +
				": " + e.getMessage(), e);
		}
		return;
	}

	/**
	 * Get a description of an external reference at the given address
	 * @param addr is the given address
	 * @param resultEncoder will contain the resulting description
	 */
	public void getExternalRef(Address addr, Encoder resultEncoder) {
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
						encodeResult(resultEncoder, shellSymbol, null);
						return;
					}
				}
				else {
					func = listing.getFunctionAt(addr);
				}
			}
			if (func == null) {
				// Its conceivable we could have external data, but we aren't currently checking for it
				return;
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
			encodeResult(resultEncoder, funcSymbol, namespc);
			return;
		}
		catch (Exception e) {
			Msg.error(this,
				"Decompiling " + funcEntry + ", error in getExternalRef: " + e.getMessage(), e);
		}
	}

	/**
	 * Get a description of a data-type given its name and type id
	 * @param name is the name of the data-type
	 * @param id is the type id
	 * @param resultEncoder will contain the resulting description
	 * @throws IOException for errors in the underlying stream while encoding
	 */
	public void getDataType(String name, long id, Encoder resultEncoder) throws IOException {
		DataType type = dtmanage.findBaseType(name, id);
		if (type == null) {
			return;
		}
		dtmanage.encodeType(resultEncoder, type, 0);
		if (debug != null) {
			debug.getType(type);
		}
	}

	/**
	 * Return a description of the register with the given name
	 * @param name is the given name
	 * @param resultEncoder is where to write the description
	 * @throws IOException for errors writing to the underlying stream
	 */
	public void getRegister(String name, Encoder resultEncoder) throws IOException {
		Register reg = pcodelanguage.getRegister(name);
		if (reg == null) {
			throw new RuntimeException("No Register Defined: " + name);
		}
		encodeRegister(resultEncoder, reg);
	}

	/**
	 * Given a storage location, return the register name for that location, or null if there
	 * is no register there.
	 * @param addr is the starting address of the storage location
	 * @param size is the size of storage in bytes
	 * @return the register name or null
	 */
	public String getRegisterName(Address addr, int size) {
		Register reg = pcodelanguage.getRegister(addr, size);
		if (reg == null) {
			return "";
		}
		return reg.getName();
	}

	/**
	 * Get "tracked" register values, constant values associated with a specific register at
	 * a specific point in the code.
	 * @param addr is the "point" in the code to look for tracked values
	 * @param resultEncoder will hold the resulting description of registers and values
	 * @throws IOException for errors in the underlying stream writing the result
	 */
	public void getTrackedRegisters(Address addr, Encoder resultEncoder) throws IOException {
		ProgramContext context = program.getProgramContext();

		encodeTrackedPointSet(resultEncoder, addr, context);
		if (debug != null) {
			XmlEncode xmlEncode = new XmlEncode();
			encodeTrackedPointSet(xmlEncode, addr, context);
			debug.getTrackedRegisters(xmlEncode.toString());
		}
	}

	/**
	 * Get the name of a user op given its index
	 * @param index is the given index
	 * @return the userop name or null
	 */
	public String getUserOpName(int index) {
		String name = pcodelanguage.getUserDefinedOpName(index);
		return name;
	}

	private void encodeResult(Encoder encoder, HighSymbol highSymbol, Namespace namespc)
			throws IOException {
		long namespaceId;
		if (namespc == null || namespc instanceof Library) {
			namespaceId = Namespace.GLOBAL_NAMESPACE_ID;
		}
		else {
			namespaceId = namespc.getID();
		}
		encoder.openElement(ELEM_DOC);
		encoder.writeUnsignedInteger(ATTRIB_ID, namespaceId);
		if (debug != null) {
			XmlEncode debugEncode = new XmlEncode();
			HighSymbol.encodeMapSym(debugEncode, highSymbol);
			String res2string = debugEncode.toString();
			debug.getMapped(namespc, res2string);
		}
		HighSymbol.encodeMapSym(encoder, highSymbol);
		encoder.closeElement(ELEM_DOC);
	}

	/**
	 * Encode a global variable to the stream
	 * @param encoder is the stream encoder
	 * @param data describes the global variable
	 * @return true if the variable is successfully encoded
	 * @throws IOException for errors in the underlying stream
	 */
	private boolean encodeData(Encoder encoder, Data data) throws IOException {
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
				return false;
			}
		}
		if (debug != null) {
			debug.getType(highSymbol.getDataType());
		}
		Namespace namespc = (sym != null) ? sym.getParentNamespace() : null;
		encodeResult(encoder, highSymbol, namespc);
		return true;
	}

	private static void encodeRegister(Encoder encoder, Register reg) throws IOException {
		encoder.openElement(ELEM_ADDR);
		encoder.writeSpace(ATTRIB_SPACE, reg.getAddressSpace());
		encoder.writeUnsignedInteger(ATTRIB_OFFSET, reg.getOffset());
		encoder.writeSignedInteger(ATTRIB_SIZE, reg.getMinimumByteSize());
		encoder.closeElement(ELEM_ADDR);
	}

	/**
	 * Encode a description of a non-data symbol, probably a code label, to the stream
	 * 
	 * @param encoder is the stream encoder
	 * @param sym is the symbol
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeLabel(Encoder encoder, Symbol sym, Address addr) throws IOException {
		HighSymbol labelSymbol = new HighLabelSymbol(sym.getName(), addr, dtmanage);
		Namespace namespc = sym.getParentNamespace();
		encodeResult(encoder, labelSymbol, namespc);
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
	 * This function deals with the vagaries of the getMappedSymbols
	 * interface when the queried address is in the body of a function.
	 * Basically, if the address is the entry point of the function, all the
	 * function data is sent. Otherwise a hole is sent back of the biggest
	 * contiguous block in the body of the function containing the queried
	 * address
	 * 
	 * @param encoder is the stream encoder
	 * @param func Function whose body contains the address
	 * @param addr The queried address
	 * @param includeDefaultNames true if default parameter names should be
	 *            included
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeFunction(Encoder encoder, Function func, Address addr,
			boolean includeDefaultNames) throws IOException {
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
				encodeResult(encoder, functionSymbol, namespc);
				return;
			}
		}

		AddressRangeIterator iter = func.getBody().getAddressRanges();
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			if (range.contains(addr)) {
				Address first = range.getMinAddress();
				Address last = range.getMaxAddress();
				boolean readonly = true; // Treat function body as readonly
				encodeHole(encoder, first.getAddressSpace(), first.getUnsignedOffset(),
					last.getUnsignedOffset(), readonly, false);
				return;
			}
		}
		// There is probably some sort of error, just return a block
		// containing the single queried address
		encodeHole(encoder, addr.getAddressSpace(), addr.getUnsignedOffset(),
			addr.getUnsignedOffset(), true, false);
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

	private void encodeHole(Encoder encoder, AddressSpace spc, long first, long last,
			boolean readonly, boolean isVolatile) throws IOException {
		encoder.openElement(ELEM_HOLE);
		encoder.writeBool(ATTRIB_READONLY, readonly);
		encoder.writeBool(ATTRIB_VOLATILE, isVolatile);
		encoder.writeSpace(ATTRIB_SPACE, spc);
		encoder.writeUnsignedInteger(ATTRIB_FIRST, first);
		encoder.writeUnsignedInteger(ATTRIB_LAST, last);
		encoder.closeElement(ELEM_HOLE);
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
	 * @param encoder is the stream encoder
	 * @param addr is the Address around which to find region
	 * @throws IOException for errors in the underlying stream
	 */
	private void encodeHole(Encoder encoder, Address addr) throws IOException {
		boolean readonly = isReadOnlyNoData(addr);
		boolean isvolatile = isVolatileNoData(addr);
		encodeHole(encoder, addr.getAddressSpace(), addr.getUnsignedOffset(),
			addr.getUnsignedOffset(), readonly, isvolatile);
	}

	private void encodeExternalRef(Encoder encoder, Address addr, ExternalReference ref)
			throws IOException {
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
		encodeResult(encoder, externSymbol, null);
	}

	private void encodeTrackSet(Encoder encoder, Register reg, long val) throws IOException {
		AddressSpace spc = reg.getAddressSpace();
		long offset = reg.getOffset();
		int size = reg.getMinimumByteSize();
		encoder.openElement(ELEM_SET);
		encoder.writeSpace(ATTRIB_SPACE, spc);
		encoder.writeUnsignedInteger(ATTRIB_OFFSET, offset);
		encoder.writeSignedInteger(ATTRIB_SIZE, size);
		encoder.writeUnsignedInteger(ATTRIB_VAL, val);
		encoder.closeElement(ELEM_SET);
	}

	private void encodeTrackedPointSet(Encoder encoder, Address addr, ProgramContext context)
			throws IOException {
		encoder.openElement(ELEM_TRACKED_POINTSET);
		AddressXML.encodeAttributes(encoder, addr);
		for (Register reg : context.getRegisters()) {
			if (reg.isProcessorContext()) {
				continue;
			}
			BigInteger val = context.getValue(reg, addr, false);
			if (val != null) {
				encodeTrackSet(encoder, reg, val.longValue());
			}
		}
		encoder.closeElement(ELEM_TRACKED_POINTSET);
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
	 * Check for a string at the given address and return a UTF8 encoded byte array.
	 * If there is already data present at the address, use this to determine the
	 * string encoding. Otherwise use the data-type info passed in to determine the encoding.
	 * Check that the bytes at the address represent a valid string encoding that doesn't
	 * exceed the maximum character limit passed in.  Return null if the string is invalid.
	 * Return the string translated into a UTF8 byte array otherwise.  A (valid) empty
	 * string is returned as a zero length array.
	 * @param addr is the given address
	 * @param maxChars is the maximum character limit
	 * @param dtName is the name of a character data-type
	 * @param dtId is the id associated with the character data-type
	 * @return the UTF8 encoded byte array or null
	 */
	public StringData getStringData(Address addr, int maxChars, String dtName, long dtId) {
		if (addr == Address.NO_ADDRESS) {
			Msg.error(this, "Address does not physically map");
			return null;
		}
		Data data = program.getListing().getDataContaining(addr);
		StringDataInstance stringInstance = StringDataInstance.getStringDataInstance(data);
		if (stringInstance != StringDataInstance.NULL_INSTANCE) {
			long diff =
				addr.subtract(data.getAddress()) * addr.getAddressSpace().getAddressableUnitSize();
			int length = data.getLength();
			if (length <= 0 || diff < 0 || diff >= length) {
				return null;
			}
			stringInstance = stringInstance.getByteOffcut((int) diff);
		}
		else {
			// There is no string and/or something else at the address.
			// Setup StringDataInstance based on raw memory
			AbstractStringDataType dt = coerceToStringDataType(dtmanage.findBaseType(dtName, dtId));
			MemoryBufferImpl buf = new MemoryBufferImpl(program.getMemory(), addr, 64);
			stringInstance = dt.getStringDataInstance(buf, SettingsImpl.NO_SETTINGS, maxChars);
			int length = stringInstance.getStringLength();
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
		StringData stringData = new StringData(stringVal, maxChars);
		if (debug != null) {
			debug.getStringData(addr, stringData);
		}
		return stringData;
	}

	private AbstractStringDataType coerceToStringDataType(DataType dt) {
		if (dt instanceof AbstractStringDataType asdt) {
			return asdt;
		}

		int size = -1;
		if (dt != null) {
			if (dt instanceof Array arrayDT) {
				dt = arrayDT.getDataType();
			}
			size = dt.getLength();
		}
		return switch (size) {
			default -> TerminatedStringDataType.dataType;
			case 2 -> TerminatedUnicodeDataType.dataType;
			case 4 -> TerminatedUnicode32DataType.dataType;
		};
	}
}
