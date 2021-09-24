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

import java.io.*;
import java.util.*;
import java.util.Map.Entry;

import ghidra.app.decompiler.DecompileCallback.StringData;
import ghidra.app.plugin.processors.sleigh.ContextCache;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.symbol.ContextSymbol;
import ghidra.app.plugin.processors.sleigh.symbol.Symbol;
import ghidra.app.util.DataTypeDependencyOrderer;
import ghidra.program.model.address.*;
import ghidra.program.model.data.BuiltIn;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Msg;
import ghidra.util.xml.SpecXmlUtils;

/**
 * A container for collecting communication between the decompiler and the Ghidra database,
 * as serviced through DecompileCallback during decompilation of a function.
 * The query results can then be dumped as an XML document.
 * The container is populated through methods that mirror the various methods in DecompileCallback.
 */
public class DecompileDebug {
	private Function func;					// The function being decompiled
	private Program program;				// The program
	private File debugFile;					// The file to dump the XML document to
	private Map<String, Object> specExtensions;	// Local extensions to the compiler spec
	private ArrayList<Namespace> dbscope;	// Symbol query:  scope
	private ArrayList<String> database;		//                description of the symbol
	private ArrayList<DataType> dtypes;		// Data-types queried
	private ArrayList<String> context;		// Tracked register values associated with an address
	private ArrayList<String> cpool;		// Constant pool results
	private ArrayList<String> flowoverride;	// Flow overrides associated with an address
	private ArrayList<String> inject;		// Injection payloads
	private TreeSet<ByteChunk> byteset;		// Load image bytes
	private TreeSet<Address> contextchange;	// Addresses at which there is a context change
	private TreeMap<Address, StringData> stringmap;	// Strings queried with their associated start address
	private Register contextRegister;		// The global context register
	private ProgramContext progctx;			// Program context
	private String comments;				// All comments associated with the function (in XML form)
	private Namespace globalnamespace;		// The global namespace
	private AddressRange readonlycache;		// Current range of addresses with same readonly value (for internal use)
	private boolean readonlycacheval;		//    Current readonly value (for internal use) 
	private PcodeDataTypeManager dtmanage;	// Decompiler's data-type manager

	class ByteChunk implements Comparable<ByteChunk> {
		public Address addr;
		public int min, max;
		public byte[] val;

		public ByteChunk(Address ad, int off, byte[] v) {
			addr = ad.getNewAddress(ad.getOffset() & ~15L);
			val = new byte[16];
			min = (int) ad.getOffset() & 15;
			int len = v.length - off;
			if (min + len >= 16) {
				len = 16 - min;
			}
			max = min + len;
			for (int i = 0; i < 16; ++i) {
				val[i] = 0;
			}
			for (int i = 0; i < len; ++i) {
				val[min + i] = v[off + i];
			}
		}

		public void merge(ByteChunk op2) {
			for (int i = op2.min; i < op2.max; ++i) {
				val[i] = op2.val[i];
			}
			if (op2.min < min) {
				min = op2.min;
			}
			if (op2.max > max) {
				max = op2.max;
			}
		}

		@Override
		public int compareTo(ByteChunk op2) {
			return addr.compareTo(op2.addr);
		}
	}

	public DecompileDebug(File debugf) {
		func = null;
		debugFile = debugf;
		specExtensions = new TreeMap<>();
		dbscope = new ArrayList<>();
		database = new ArrayList<>();
		dtypes = new ArrayList<>();
		context = new ArrayList<>();
		cpool = new ArrayList<>();
		byteset = new TreeSet<>();
		contextchange = new TreeSet<>();
		stringmap = new TreeMap<>();
		flowoverride = new ArrayList<>();
		inject = new ArrayList<>();
		contextRegister = null;
		comments = null;
		globalnamespace = null;
		readonlycache = null;
		readonlycacheval = false;
	}

	public void setFunction(Function f) {
		func = f;
		program = f.getProgram();
		progctx = program.getProgramContext();
		contextRegister = progctx.getBaseContextRegister();
		globalnamespace = program.getGlobalNamespace();
	}

	public void setPcodeDataTypeManager(PcodeDataTypeManager dtm) {
		dtmanage = dtm;
	}

	public void shutdown(Language pcodelanguage, String xmlOptions) {
		OutputStream debugStream;
		if (debugFile.exists()) {
			debugFile.delete();
		}
		try {
			debugStream = new BufferedOutputStream(new FileOutputStream(debugFile));
		}
		catch (FileNotFoundException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			return;
		}
		try {
			StringBuilder buf = new StringBuilder();
			buf.append("<xml_savefile");
			SpecXmlUtils.xmlEscapeAttribute(buf, "name", func.getName());
			SpecXmlUtils.encodeStringAttribute(buf, "target", "default");
			SpecXmlUtils.encodeSignedIntegerAttribute(buf, "adjustvma", 0);
			buf.append(">\n");
			debugStream.write(buf.toString().getBytes());
			dumpImage(debugStream, pcodelanguage);
			dumpExtensions(debugStream);
			dumpCoretypes(debugStream);
			debugStream.write("<save_state>\n".getBytes());
//			dumpTypes(debugStream);
			dumpDataTypes(debugStream);
			dumpDatabases(debugStream);
			debugStream.write("<context_points>\n".getBytes());
			dumpPointsetContext(debugStream);
			dumpTrackedContext(debugStream);
			debugStream.write("</context_points>\n".getBytes());
			dumpComments(debugStream);
			dumpStringData(debugStream);
			dumpCPool(debugStream);
			dumpConfiguration(debugStream, xmlOptions);
			dumpFlowOverride(debugStream);
			dumpInject(debugStream);
			debugStream.write("</save_state>\n".getBytes());
			debugStream.write("</xml_savefile>\n".getBytes());
			debugStream.close();
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	private void dumpImage(OutputStream debugStream, Language pcodelanguage) throws IOException {
		String binimage = "<binaryimage arch=\"";
		binimage += pcodelanguage.getLanguageID();
		binimage += ':';
		binimage += program.getCompilerSpec().getCompilerSpecID();
		binimage += "\">\n";
		debugStream.write(binimage.getBytes());
		dumpBytes(debugStream);
		debugStream.write("</binaryimage>\n".getBytes());
	}

	private boolean isReadOnly(Address addr) {
		if ((readonlycache != null) && (readonlycache.contains(addr))) {
			return readonlycacheval;
		}
		MemoryBlock block = program.getMemory().getBlock(addr);
		readonlycache = null;
		readonlycacheval = false;
		if (block != null) {
			readonlycacheval = !block.isWrite();
			readonlycache = new AddressRangeImpl(block.getStart(), block.getEnd());
		}
		return readonlycacheval;
	}

	private void dumpBytes(OutputStream debugStream) throws IOException {
		StringBuilder buf = new StringBuilder();
		Iterator<ByteChunk> iter = byteset.iterator();
		AddressSpace lastspace = null;
		long lastoffset = 0;
		boolean lastreadonly = false;
		boolean tagstarted = false;
		while (iter.hasNext()) {
			ByteChunk chunk = iter.next();
			AddressSpace space = chunk.addr.getAddressSpace();
			boolean readval = isReadOnly(chunk.addr);
			if (lastreadonly != readval) {
				lastspace = null;		// Force a break in chunk, so we can set new readonly value
				lastreadonly = readval;
			}

			if (tagstarted && ((chunk.min != 0) || (lastspace != space) ||
				(lastoffset != chunk.addr.getOffset()))) {
				buf.append("\n</bytechunk>\n");
				tagstarted = false;
			}
			if (!tagstarted) {
				buf.append("<bytechunk");
				SpecXmlUtils.encodeStringAttribute(buf, "space",
					space.getPhysicalSpace().getName());
				SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "offset",
					chunk.addr.getOffset() + chunk.min);
				if (lastreadonly) {
					SpecXmlUtils.encodeBooleanAttribute(buf, "readonly", lastreadonly);
				}
				buf.append(">\n");
				tagstarted = true;
			}
			for (int i = 0; i < chunk.min; ++i) {
				buf.append("  ");					// pad the hex display to 16 bytes
			}
			for (int i = chunk.min; i < chunk.max; ++i) {
				int hi = (chunk.val[i] >> 4) & 0xf;
				int lo = chunk.val[i] & 0xf;
				if (hi > 9) {
					hi += 'a' - 10;
				}
				else {
					hi += '0';
				}
				if (lo > 9) {
					lo += 'a' - 10;
				}
				else {
					lo += '0';
				}
				buf.append((char) hi);
				buf.append((char) lo);
			}
			buf.append('\n');
			if (chunk.max != 16) {
				buf.append("</bytechunk>\n");
				tagstarted = false;
			}
			else {
				lastoffset = chunk.addr.getOffset() + 16;
				lastspace = space;
			}
		}
		if (tagstarted) {
			buf.append("</bytechunk>\n");
		}
		debugStream.write(buf.toString().getBytes());
	}

	/**
	 * Dump information on strings that were queried by the decompiler.
	 * @param debugStream is the stream to write to
	 * @throws IOException if any i/o error occurs
	 */
	private void dumpStringData(OutputStream debugStream) throws IOException {
		if (stringmap.isEmpty()) {
			return;
		}
		StringBuilder buf = new StringBuilder();
		buf.append("<stringmanage>\n");
		for (Map.Entry<Address, StringData> entry : stringmap.entrySet()) {
			buf.append("<string>\n");
			AddressXML.buildXML(buf, entry.getKey());
			buf.append("\n<bytes");
			SpecXmlUtils.encodeBooleanAttribute(buf, "trunc", entry.getValue().isTruncated);
			buf.append(">\n  ");
			int count = 0;
			for (byte element : entry.getValue().byteData) {
				int hi = (element >> 4) & 0xf;
				int lo = element & 0xf;
				if (hi > 9) {
					hi += 'a' - 10;
				}
				else {
					hi += '0';
				}
				if (lo > 9) {
					lo += 'a' - 10;
				}
				else {
					lo += '0';
				}
				buf.append((char) hi);
				buf.append((char) lo);
				if (count % 20 == 19) {
					buf.append("\n  ");
				}
			}
			buf.append("00\n</bytes>\n");
			buf.append("</string>\n");
		}
		buf.append("</stringmanage>\n");
		debugStream.write(buf.toString().getBytes());
	}

	private void dumpDataTypes(OutputStream debugStream) throws IOException {
		int intSize = program.getCompilerSpec().getDataOrganization().getIntegerSize();
		StringBuilder buf = new StringBuilder();
		buf.append("<typegrp");
		SpecXmlUtils.encodeSignedIntegerAttribute(buf, "intsize", intSize);
		SpecXmlUtils.encodeSignedIntegerAttribute(buf, "structalign", 4);
		SpecXmlUtils.encodeSignedIntegerAttribute(buf, "enumsize", 4);
		SpecXmlUtils.encodeBooleanAttribute(buf, "enumsigned", false);
		buf.append(">\n");
		// structalign should come out of pcodelanguage.getCompilerSpec()
		debugStream.write(buf.toString().getBytes());
		DataTypeDependencyOrderer TypeOrderer =
			new DataTypeDependencyOrderer(program.getDataTypeManager(), dtypes);
		//First output all structures as zero size so to avoid any cyclic dependencies.
		for (DataType dataType : TypeOrderer.getStructList()) {
			debugStream.write(
				(dtmanage.buildStructTypeZeroSizeOveride(dataType) + "\n").toString().getBytes());
		}
		//Next, use the dependency stack to output types.
		for (DataType dataType : TypeOrderer.getDependencyList()) {
			if (!(dataType instanceof BuiltIn)) {
				StringBuilder typeBuf = new StringBuilder();

				dtmanage.buildType(typeBuf, dataType, dataType.getLength());
				typeBuf.append('\n');
				debugStream.write(typeBuf.toString().getBytes());
			}
		}
		debugStream.write("</typegrp>\n".getBytes());
	}

	private void dumpTrackedContext(OutputStream debugStream) throws IOException {
		// There is only one set of tracked registers, the
		// set associated with the function start
		// and it is written in xml as if it were
		// the default tracking set
		for (String element : context) {
			debugStream.write((element).getBytes());
		}
	}

	private ArrayList<ContextSymbol> getContextSymbols() {
		Language lang = program.getLanguage();
		if (!(lang instanceof SleighLanguage)) {
			return null;
		}
		ArrayList<ContextSymbol> res = new ArrayList<>();
		ghidra.app.plugin.processors.sleigh.symbol.Symbol[] list =
			((SleighLanguage) lang).getSymbolTable().getSymbolList();
		for (Symbol element : list) {
			if (element instanceof ContextSymbol) {
				res.add((ContextSymbol) element);
			}
		}
		return res;
	}

	/**
	 * Add the starting address of the range of addresses over which all of context remains
	 * constant and has the same value as the value at -addr-
	 * @param addr is an Address contained in the constant range
	 */
	private void getContextChangePoints(Address addr) {
		AddressRange addrrange = progctx.getRegisterValueRangeContaining(contextRegister, addr);
		if (addrrange == null) {
			return;
		}
		contextchange.add(addrrange.getMinAddress());
		try {
			Address nextaddr = addrrange.getMaxAddress().add(1);
			contextchange.add(nextaddr);
		}
		catch (AddressOutOfBoundsException msg) {  // If adding 1 is out of bounds we don't need another change point
		}
	}

	/**
	 * This routine collects all the context register changes across the
	 * body of the function. Right now we only get the context at the
	 * beginning of the function because its difficult to tell where the
	 * context changes.
	 * @param debugStream is the stream being written to
	 * @throws IOException for any i/o error
	 */
	private void dumpPointsetContext(OutputStream debugStream) throws IOException {
		ArrayList<ContextSymbol> ctxsymbols = getContextSymbols();
		if (ctxsymbols == null) {
			return;
		}
		ContextCache ctxcache = new ContextCache();
		ctxcache.registerVariable(contextRegister);
		int[] buf = new int[ctxcache.getContextSize()];
		int[] lastbuf = null;

		Iterator<Address> iter = contextchange.iterator();
		while (iter.hasNext()) {
			Address addr = iter.next();
			ProgramProcessorContext procctx = new ProgramProcessorContext(progctx, addr);
			ctxcache.getContext(procctx, buf);
			StringBuilder stringBuf = new StringBuilder();
			if (lastbuf != null) {		// Check to make sure we don't have identical context data
				int i;
				for (i = 0; i < buf.length; ++i) {
					if (buf[i] != lastbuf[i]) {
						break;
					}
				}
				if (i == buf.length) {
					continue;	// If all data is identical, then changepoint is not necessary
				}
			}
			else {
				lastbuf = new int[buf.length];
			}
			for (int i = 0; i < buf.length; ++i) {
				lastbuf[i] = buf[i];
			}

			stringBuf.append("<context_pointset");
			AddressXML.appendAttributes(stringBuf, addr);
			stringBuf.append(">\n");
			for (ContextSymbol sym : ctxsymbols) {
				int sbit = sym.getInternalLow();
				int ebit = sym.getInternalHigh();
				int word = sbit / (8 * 4);
				int startbit = sbit - word * (8 * 4);
				int endbit = ebit - word * (8 * 4);
				int shift = (8 * 4) - endbit - 1;
				int mask = -1 >>> (startbit + shift);
				int val = (buf[word] >>> shift) & mask;
				stringBuf.append("  <set");
				SpecXmlUtils.encodeStringAttribute(stringBuf, "name", sym.getName());
				SpecXmlUtils.encodeSignedIntegerAttribute(stringBuf, "val", val);
				stringBuf.append("/>\n");
			}
			stringBuf.append("</context_pointset>\n");
			String end = stringBuf.toString();
			debugStream.write(end.getBytes());
		}
	}

	private void dumpCPool(OutputStream debugStream) throws IOException {
		if (cpool.size() == 0) {
			return;
		}
		debugStream.write("<constantpool>\n".getBytes());
		for (String rec : cpool) {
			debugStream.write(rec.getBytes());
		}
		debugStream.write("</constantpool>\n".getBytes());
	}

	private void dumpComments(OutputStream debugStream) throws IOException {
		if (comments != null) {
			debugStream.write(comments.getBytes());
		}
	}

	private void dumpConfiguration(OutputStream debugStream, String xmlOptions) throws IOException {
		if ((xmlOptions != null) && (xmlOptions.length() != 0)) {
			debugStream.write(xmlOptions.getBytes());
		}
	}

	private void dumpFlowOverride(OutputStream debugStream) throws IOException {
		if (flowoverride.size() == 0) {
			return;
		}
		debugStream.write("<flowoverridelist>\n".getBytes());
		for (String element : flowoverride) {
			debugStream.write(element.getBytes());
		}

		debugStream.write("</flowoverridelist>\n".getBytes());
	}

	private void dumpInject(OutputStream debugStream) throws IOException {
		if (inject.size() == 0) {
			return;
		}
		debugStream.write("<injectdebug>\n".getBytes());
		for (String element : inject) {
			debugStream.write(element.getBytes());
		}
		debugStream.write("</injectdebug>\n".getBytes());
	}

	private ArrayList<Namespace> orderNamespaces() {
		TreeMap<Long, Namespace> namespaceMap = new TreeMap<>();
		for (Namespace namespace : dbscope) {
			namespaceMap.put(namespace.getID(), namespace);
		}
		ArrayList<Namespace> res = new ArrayList<>();
		while (!namespaceMap.isEmpty()) {
			Entry<Long, Namespace> entry = namespaceMap.firstEntry();
			Long curKey = entry.getKey();
			Namespace curSpace = entry.getValue();
			for (;;) {
				Long key;
				Namespace parent = curSpace.getParentNamespace();
				if (parent == null) {
					break;
				}
				if (HighFunction.collapseToGlobal(parent)) {
					key = Long.valueOf(Namespace.GLOBAL_NAMESPACE_ID);
				}
				else {
					key = Long.valueOf(parent.getID());
				}
				parent = namespaceMap.get(key);
				if (parent == null) {
					break;
				}
				curKey = key;
				curSpace = parent;
			}
			res.add(curSpace);
			namespaceMap.remove(curKey);
		}
		return res;
	}

	private void dumpDatabases(OutputStream debugStream) throws IOException {
		Namespace scopename = null;
		ArrayList<Namespace> spaceList = orderNamespaces();
		debugStream.write("<db scodeidbyname=\"false\">\n".getBytes());
		for (Namespace element : spaceList) {
			scopename = element;
			StringBuilder datahead = new StringBuilder();
			Namespace parentNamespace;
			datahead.append("<scope");
			// Force globalnamespace to have blank name
			if (scopename != globalnamespace) {
				SpecXmlUtils.xmlEscapeAttribute(datahead, "name", scopename.getName());
				parentNamespace = scopename.getParentNamespace();
				SpecXmlUtils.encodeUnsignedIntegerAttribute(datahead, "id", scopename.getID());
			}
			else {
				SpecXmlUtils.encodeStringAttribute(datahead, "name", "");
				SpecXmlUtils.encodeUnsignedIntegerAttribute(datahead, "id",
					Namespace.GLOBAL_NAMESPACE_ID);
				parentNamespace = null;
			}
			datahead.append(">\n");
			if (parentNamespace != null) {
				long parentId =
					HighFunction.collapseToGlobal(parentNamespace) ? Namespace.GLOBAL_NAMESPACE_ID
							: parentNamespace.getID();
				datahead.append("<parent");
				SpecXmlUtils.encodeUnsignedIntegerAttribute(datahead, "id", parentId);
				datahead.append("/>\n");
			}
			if (scopename != globalnamespace) {
				datahead.append("<rangeequalssymbols/>\n");
			}
			datahead.append("<symbollist>\n");
			debugStream.write(datahead.toString().getBytes());
			for (int j = 0; j < database.size(); ++j) {
				Namespace namespc = dbscope.get(j);
				if (namespc == scopename) {
					String entry = database.get(j);
					if (entry == null) {
						continue;			// String may be null
					}
					debugStream.write(entry.getBytes());
				}
			}
			debugStream.write("</symbollist>\n</scope>\n".getBytes());
		}
		debugStream.write("</db>\n".getBytes());
	}

	private void dumpExtensions(OutputStream debugStream) throws IOException {
		if (specExtensions.isEmpty()) {
			return;
		}
		PcodeInjectLibrary library = program.getCompilerSpec().getPcodeInjectLibrary();
		debugStream.write("<specextensions>\n".getBytes());
		for (Object obj : specExtensions.values()) {
			if (obj instanceof PrototypeModel) {
				PrototypeModel model = (PrototypeModel) obj;
				StringBuilder buffer = new StringBuilder();
				model.saveXml(buffer, library);
				String modelString = buffer.toString();
				debugStream.write(modelString.getBytes());
			}
			else if (obj instanceof InjectPayload) {
				InjectPayload payload = (InjectPayload) obj;
				StringBuilder buffer = new StringBuilder();
				payload.saveXml(buffer);
				String payloadString = buffer.toString();
				debugStream.write(payloadString.getBytes());
			}
		}
		debugStream.write("</specextensions>\n".getBytes());
	}

	private void dumpCoretypes(OutputStream debugStream) throws IOException {
		debugStream.write(dtmanage.buildCoreTypes().getBytes());
	}

	public void getPcode(Address addr, Instruction instr) {
		if (instr != null) {
			try {
				byte[] bytes;
				int delaySlotsCnt = instr.getDelaySlotDepth();
				if (delaySlotsCnt == 0) {
					bytes = instr.getBytes();
				}
				else {
					// Include delay slot bytes with instruction bytes
					Listing listing = instr.getProgram().getListing();
					int byteCnt = instr.getLength();
					Instruction[] instructions = new Instruction[delaySlotsCnt + 1];
					instructions[0] = instr;
					Address nextAddr = instr.getMaxAddress().add(1);
					for (int i = 1; i <= delaySlotsCnt; i++) {
						instructions[i] = listing.getInstructionAt(nextAddr);
						int len = instructions[i].getLength();
						byteCnt += len;
						nextAddr.add(len);
					}
					bytes = new byte[byteCnt];
					byteCnt = 0;
					for (int i = 0; i <= delaySlotsCnt; i++) {
						byte[] b = instructions[i].getBytes();
						System.arraycopy(b, 0, bytes, byteCnt, b.length);
						byteCnt += b.length;
					}
				}
				getBytes(addr, bytes);
				getContextChangePoints(addr);
			}
			catch (MemoryAccessException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
		}
	}

	public void getBytes(Address addr, byte[] res) {
		int off = 0;
		while (off < res.length) {
			ByteChunk chunk = new ByteChunk(addr, off, res);

			if (byteset.contains(chunk)) {		// Seen this chunk before
				ByteChunk match = byteset.tailSet(chunk).first();
				match.merge(chunk);
			}
			else {
				byteset.add(chunk);
			}
			Address newaddr = chunk.addr.add(chunk.max);
			off += newaddr.getOffset() - addr.getOffset();
			addr = newaddr;
		}
	}

	public void getStringData(Address addr, StringData stringData) {
		stringmap.put(addr, stringData);
	}

	public void getComments(String comm) {
		comments = comm;	// Already in XML form
	}

	public void getCodeSymbol(Address addr, long id, String name, Namespace namespace) {
		StringBuilder buf = new StringBuilder();
		buf.append("<mapsym>\n");
		buf.append(" <labelsym");
		SpecXmlUtils.xmlEscapeAttribute(buf, "name", name);
		SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "id", id);
		buf.append("/>\n ");
		AddressXML.buildXML(buf, addr);
		buf.append("\n <rangelist/>\n");
		buf.append("</mapsym>\n");
		getMapped(namespace, buf.toString());
	}

	public void getNamespacePath(Namespace namespace) {
		while (namespace != null) {
			if (HighFunction.collapseToGlobal(namespace)) {
				break;		// Treat library namespace as root
			}
			dbscope.add(namespace);		// Add namespace to guarantee <scope> tag
			database.add(null);			// Even if there isn't necessarily any symbols
			namespace = namespace.getParentNamespace();
		}
	}

	public void getMapped(Namespace namespc, String res) {
		if (namespc == null || HighFunction.collapseToGlobal(namespc)) {
			dbscope.add(globalnamespace);
		}
		else {
			dbscope.add(namespc);
		}
		database.add(res);
	}

	public void getType(DataType dt) {
		dtypes.add(dt);
	}

	public void getFNTypes(HighFunction hfunc) {
		getType(hfunc.getFunctionPrototype().getReturnType());
		for (int i = 0; i < hfunc.getFunctionPrototype().getNumParams(); i++) {
			getType(hfunc.getFunctionPrototype().getParam(i).getDataType());
		}
	}

	public void getTrackedRegisters(String doc) {
		context.add(doc);
	}

	public void getCPoolRef(String rec, long[] refs) {
		StringBuilder buf = new StringBuilder();
		buf.append("<ref");
		SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "a", refs[0]);
		long val = 0;
		if (refs.length > 1) {
			val = refs[1];
		}
		SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "b", val);
		buf.append("/>\n");
		buf.append(rec);
		cpool.add(buf.toString());
	}

	public void nameIsUsed(Namespace spc, String nm) {
		StringBuilder buffer = new StringBuilder();
		buffer.append("<collision");
		SpecXmlUtils.xmlEscapeAttribute(buffer, "name", nm);
		buffer.append("/>\n");
		getMapped(spc, buffer.toString());
	}

	public void addFlowOverride(Address addr, FlowOverride fo) {
		StringBuilder buf = new StringBuilder();
		buf.append("<flow type=\"");
		if (fo == FlowOverride.BRANCH) {
			buf.append("branch");
		}
		else if (fo == FlowOverride.CALL) {
			buf.append("call");
		}
		else if (fo == FlowOverride.CALL_RETURN) {
			buf.append("callreturn");
		}
		else if (fo == FlowOverride.RETURN) {
			buf.append("return");
		}
		else {
			buf.append("none");
		}
		buf.append("\">");
		AddressXML.buildXML(buf, func.getEntryPoint());
		AddressXML.buildXML(buf, addr);
		buf.append("</flow>\n");
		flowoverride.add(buf.toString());
	}

	public void addInject(Address addr, String name, int injectType, String payload) {
		StringBuilder buf = new StringBuilder();
		buf.append("<inject name=\"");
		buf.append(name);
		buf.append('"');
		SpecXmlUtils.encodeSignedIntegerAttribute(buf, "type", injectType);
		buf.append(">\n  ");
		AddressXML.buildXML(buf, addr);
		buf.append("\n  <payload><![CDATA[\n");
		buf.append(payload);
		buf.append("\n]]></payload>\n</inject>\n");
		inject.add(buf.toString());

		PcodeInjectLibrary library = program.getCompilerSpec().getPcodeInjectLibrary();
		if (library.hasProgramPayload(name, injectType)) {
			InjectPayload programPayload = library.getPayload(injectType, name);
			String title =
				(injectType == InjectPayload.CALLFIXUP_TYPE) ? "callfixup_" : "callotherfixup_";
			title = title + name;
			specExtensions.put(title, programPayload);
		}
	}

	public void addPossiblePrototypeExtension(Function testFunc) {
		PrototypeModel model = testFunc.getCallingConvention();
		if (model == null) {
			return;
		}
		if (model.isProgramExtension()) {
			String title = "prototype_" + model.getName();
			specExtensions.put(title, model);
		}
	}
}
