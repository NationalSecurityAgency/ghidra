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
//Decompile the function at the cursor and its callees, then output facts files corresponding to the pcodes
//@category PCode

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompileConfigurer;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.graph.GVertex;
import ghidra.graph.GraphFactory;
import ghidra.graph.algo.DepthFirstSorter;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.ThunkReference;
import ghidra.util.task.TaskMonitor;

class PcodeBlockBasicVertex implements GVertex {
	private PcodeBlock bb;

	public PcodeBlockBasicVertex(PcodeBlock bb) {
		this.bb = bb;
	}

	public PcodeBlockBasic bb() {
		return (PcodeBlockBasic) bb;
	}
}

class PcodeBlockBasicEdge implements GEdge<PcodeBlockBasicVertex> {
	private PcodeBlockBasicVertex start;
	private PcodeBlockBasicVertex end;

	public PcodeBlockBasicEdge(PcodeBlockBasicVertex start, PcodeBlockBasicVertex end) {
		this.start = start;
		this.end = end;
	}

	public PcodeBlockBasicVertex getStart() {
		return start;
	}

	public PcodeBlockBasicVertex getEnd() {
		return end;
	}
}

class DecompilerConfigurer implements DecompileConfigurer {

	DecompInterface ifc;

	DecompilerConfigurer(Program p) {
	}

	@Override
	public void configure(DecompInterface decompiler) {
		this.ifc = decompiler;
		DecompileOptions options = new DecompileOptions();
		decompiler.setOptions(options);
		decompiler.setSimplificationStyle("decompile"); // can also use "normalize" but that won't generate
														// HighVariables
	}

	DecompInterface getInteface() {
		return ifc;
	}

}

enum PredicateFile {
	LANGUAGE("CTADLLanguage"), HFUNC_LOCAL_EP("HFUNC_LOCAL_EP"), HFUNC_FUNC("HFUNC_FUNC"), HFUNC_TOSTR("HFUNC_TOSTR"),
	HFUNC_PROTO("HFUNC_PROTO"), HFUNC_ISEP("HFUNC_ISEP"), HFUNC_ISEXT("HFUNC_ISEXT"), HFUNC_CSPEC("HFUNC_CSPEC"),
	HFUNC_EP("HFUNC_EP"), HFUNC_LANG("HFUNC_LANG"), HFUNC_NAME("HFUNC_NAME"), HVAR_NAME("HVAR_NAME"),
	HVAR_SIZE("HVAR_SIZE"), HVAR_CLASS("HVAR_CLASS"), HVAR_SCOPE("HVAR_SCOPE"), HVAR_TYPE("HVAR_TYPE"),
	HVAR_REPRESENTATIVE("HVAR_REPRESENTATIVE"), PCODE_TOSTR("PCODE_TOSTR"), PCODE_MNEMONIC("PCODE_MNEMONIC"),
	PCODE_OPCODE("PCODE_OPCODE"), PCODE_PARENT("PCODE_PARENT"), PCODE_TARGET("PCODE_TARGET"),
	PCODE_INPUT_COUNT("PCODE_INPUT_COUNT"), PCODE_INPUT("PCODE_INPUT"), PCODE_OUTPUT("PCODE_OUTPUT"),
	PCODE_NEXT("PCODE_NEXT"), PCODE_TIME("PCODE_TIME"), PCODE_INDEX("PCODE_INDEX"), VNODE_ADDRESS("VNODE_ADDRESS"),
	VNODE_IS_ADDRESS("VNODE_IS_ADDRESS"), VNODE_IS_ADDRTIED("VNODE_IS_ADDRTIED"), VNODE_PC_ADDRESS("VNODE_PC_ADDRESS"),
	VNODE_DESC("VNODE_DESC"), VNODE_OFFSET("VNODE_OFFSET"), VNODE_OFFSET_N("VNODE_OFFSET_N"), VNODE_SIZE("VNODE_SIZE"),
	VNODE_NAME("VNODE_NAME"), VNODE_SPACE("VNODE_SPACE"), VNODE_TOSTR("VNODE_TOSTR"), VNODE_HVAR("VNODE_HVAR"),
	VNODE_DEF("VNODE_DEF"), VNODE_HFUNC("VNODE_HFUNC"), TYPE_NAME("TYPE_NAME"), TYPE_LENGTH("TYPE_LENGTH"),
	TYPE_POINTER("TYPE_POINTER"), TYPE_POINTER_BASE("TYPE_POINTER_BASE"), TYPE_ARRAY("TYPE_ARRAY"),
	TYPE_ARRAY_BASE("TYPE_ARRAY_BASE"), TYPE_ARRAY_N("TYPE_ARRAY_N"),
	TYPE_ARRAY_ELEMENT_LENGTH("TYPE_ARRAY_ELEMENT_LENGTH"), TYPE_STRUCT("TYPE_STRUCT"),
	TYPE_STRUCT_FIELD("TYPE_STRUCT_FIELD"), TYPE_STRUCT_OFFSET("TYPE_STRUCT_OFFSET"),
	TYPE_STRUCT_OFFSET_N("TYPE_STRUCT_OFFSET_N"), TYPE_STRUCT_FIELD_NAME("TYPE_STRUCT_FIELD_NAME"),
	TYPE_STRUCT_FIELD_NAME_BY_OFFSET("TYPE_STRUCT_FIELD_NAME_BY_OFFSET"),
	TYPE_STRUCT_FIELD_COUNT("TYPE_STRUCT_FIELD_COUNT"), TYPE_UNION("TYPE_UNION"), TYPE_UNION_FIELD("TYPE_UNION_FIELD"),
	TYPE_UNION_OFFSET("TYPE_UNION_OFFSET"), TYPE_UNION_OFFSET_N("TYPE_UNION_OFFSET_N"),
	TYPE_UNION_FIELD_NAME("TYPE_UNION_FIELD_NAME"), TYPE_UNION_FIELD_NAME_BY_OFFSET("TYPE_UNION_FIELD_NAME_BY_OFFSET"),
	TYPE_UNION_FIELD_COUNT("TYPE_UNION_FIELD_COUNT"), TYPE_FUNC("TYPE_FUNC"), TYPE_FUNC_RET("TYPE_FUNC_RET"),
	TYPE_FUNC_VARARGS("TYPE_FUNC_VARARGS"), TYPE_FUNC_PARAM_COUNT("TYPE_FUNC_PARAM_COUNT"),
	TYPE_FUNC_PARAM("TYPE_FUNC_PARAM"), TYPE_BOOLEAN("TYPE_BOOLEAN"), TYPE_INTEGER("TYPE_INTEGER"),
	TYPE_FLOAT("TYPE_FLOAT"), TYPE_ENUM("TYPE_ENUM"), BB_IN("BB_IN"), BB_LAST("BB_LAST"), BB_OUT("BB_OUT"),
	BB_FOUT("BB_FOUT"), BB_TOUT("BB_TOUT"), BB_FIRST("BB_FIRST"), BB_HFUNC("BB_HFUNC"), BB_START("BB_START"),
	PROTO_IS_CONSTRUCTOR("PROTO_IS_CONSTRUCTOR"), PROTO_IS_DESTRUCTOR("PROTO_IS_DESTRUCTOR"),
	PROTO_IS_VARARG("PROTO_IS_VARARG"), PROTO_IS_INLINE("PROTO_IS_INLINE"), PROTO_IS_VOID("PROTO_IS_VOID"),
	PROTO_HAS_THIS("PROTO_HAS_THIS"), PROTO_CALLING_CONVENTION("PROTO_CALLING_CONVENTION"),
	PROTO_RETTYPE("PROTO_RETTYPE"), PROTO_PARAMETER("PROTO_PARAMETER"), PROTO_PARAMETER_COUNT("PROTO_PARAMETER_COUNT"),
	PROTO_PARAMETER_DATATYPE("PROTO_PARAMETER_DATATYPE"), SYMBOL_HVAR("SYMBOL_HVAR"), SYMBOL_HFUNC("SYMBOL_HFUNC"),
	DATA_STRING("DATA_STRING"), VTABLE("VTABLE"), SYMBOL_NAME("SYMBOL_NAME"), PROGRAM_FILE("PROGRAM_FILE"), OFFSET_INDEX("OFFSET_INDEX");

	private final String name;

	PredicateFile(String name) {
		this.name = name;
	}

	@Override
	public String toString() {
		return name;
	}

	public Writer getWriter(File directory, String suffix, boolean append) throws IOException {
		File factsFile = new File(directory, name + suffix);
		if (!append)
			touch(factsFile);
		return new BufferedWriter(new FileWriter(factsFile, true));
	}

	public static void touch(File file) throws IOException {
		file.delete();
		file.createNewFile();
	}
}

class Database {
	private static final char DBSEP = '\t';
	private static final char EOL = '\n';

	protected final Map<PredicateFile, Collection<List<String>>> contents;
	protected boolean everCleared;

	public Database() {
		contents = new EnumMap<>(PredicateFile.class);
		for (PredicateFile predicateFile : EnumSet.allOf(PredicateFile.class))
			contents.put(predicateFile, new HashSet<List<String>>());
		// contents.put(predicateFile, new ArrayList<List<String>>());
		everCleared = false;
	}

	public void writeFile(Collection<List<String>> contents, PredicateFile predicateFile, String directory)
			throws IOException {
		Writer w = predicateFile.getWriter(new File(directory), ".facts", everCleared);
		for (List<String> record : contents) {
			writeRecord(w, record);
		}
		w.flush();
		w.close();
	}

	public void writeFacts(String directory, boolean writeAll) throws IOException {
		final int k = Runtime.getRuntime().availableProcessors() * 2 - 1;
		ExecutorService es = Executors.newFixedThreadPool(k);
		for (PredicateFile predicateFile : EnumSet.allOf(PredicateFile.class)) {
			if (!writeAll && predicateFile.name().startsWith("TYPE_")) {
				continue;
			}
			es.execute(() -> {
				try {
					writeFile(this.contents.get(predicateFile), predicateFile, directory);
				} catch (Exception e) {
					// System.out.println(e);
					ghidra.util.Msg.info(this, e);
					for (java.lang.StackTraceElement st : e.getStackTrace()) {
						ghidra.util.Msg.info(this, st);
					}
				}
			});
		}

		es.shutdown();
		try {
			while (!es.awaitTermination(30, TimeUnit.SECONDS))
				;
		} catch (Exception e) {
			// System.out.println(e);
			ghidra.util.Msg.info(this, e);
			for (java.lang.StackTraceElement st : e.getStackTrace()) {
				ghidra.util.Msg.info(this, st);
			}
		}

		this.clear(writeAll);
	}

	private void writeRecord(Writer writer, List<String> record) throws IOException {
		boolean first = true;
		for (String col : record) {
			if (!first) {
				writer.write(DBSEP);
			}
			writeColumn(writer, col);
			first = false;
		}
		writer.write(EOL);
	}

	private void writeColumn(Writer writer, String column) throws IOException {
		// Quote some special characters.
		final char QUOTE = '\"';
		final char SLASH = '\\';
		final char TABCH = '\t';
		for (int i = 0; i < column.length(); i++) {
			char c = column.charAt(i);
			switch (c) {
			case QUOTE:
				writer.write("'");
				break;
			case SLASH:
				writer.write('\\');
				writer.write('\\');
				break;
			case EOL:
				writer.write('\\');
				writer.write('n');
				break;
			case TABCH:
				writer.write('\\');
				writer.write('t');
				break;
			default:
				writer.write(c);
			}
		}
	}

	public void add(PredicateFile predicateFile, String... args) {
		this.contents.get(predicateFile).add(Arrays.asList(args));
	}

	public void merge(Database other) {
		for (Map.Entry<PredicateFile, Collection<List<String>>> entry : other.contents.entrySet()) {
			this.contents.get(entry.getKey()).addAll(entry.getValue());
		}

	}

	public void clear(boolean clearAll) {
		for (PredicateFile predicateFile : EnumSet.allOf(PredicateFile.class)) {
			if (!clearAll && predicateFile.name().startsWith("TYPE_")) {
				continue;
			}
			contents.put(predicateFile, new HashSet<List<String>>());
		}
		everCleared = true;
	}
}


class ItemCounter {
    private final ConcurrentHashMap<String, Integer> seenItems = new ConcurrentHashMap<>();
    private final AtomicInteger counter = new AtomicInteger(3);

    public int getUniqueNumber(String item) {
        // Check if the item has been seen
        return seenItems.computeIfAbsent(item, key -> counter.incrementAndGet());
    }
}

class HighFunctionExporter {
	private final Database db = new Database();
	private final Set<String> types = new HashSet<String>();
	private Set<String> varnodes = new HashSet<String>();
	private ItemCounter offsets = new ItemCounter();
	private final HashMap<String, PredicateFile> componentPredicates = new HashMap<String, PredicateFile>();
	private Map<HighVariable, VarnodeAST> extraGlobals = new HashMap<HighVariable, VarnodeAST>();
	private final Writer debug;
	private final String directory;
	private final Set<Address> vtables = new HashSet<Address>();

	String SEP = ":";
	String TAB = "\t";
	String QUOTE = "\"";

	public HighFunctionExporter(String directory) throws IOException {
		this.directory = directory;
		for (PredicateFile pf : PredicateFile.values()) {
			componentPredicates.put(pf.toString(), pf);
		}
		debug = new BufferedWriter(new FileWriter(new File(directory, "PcodeOps.facts")));
	}

	public void writeFacts(boolean writeAll) throws IOException {
		db.writeFacts(directory, writeAll);
	}

	public void writeDebug() throws IOException {
		debug.close();
	}

	public Database getDatabase() {
		return db;
	}

	public void processFunction(DecompileResults res, Function f, DecompInterface decompiler) {
		// System.out.println("processing " + f.getName() + SEP + f.getEntryPoint());
		varnodes = new HashSet<String>();
		extraGlobals = new HashMap<HighVariable, VarnodeAST>();

// TODO: This should only be done once if dumping the entire program
		SymbolIterator externalSymbols = f.getProgram().getSymbolTable().getSymbols(f.getName());
		while (externalSymbols.hasNext()) {
			Symbol next = externalSymbols.next();
			if (!next.isExternal()) {
				Address address = next.getAddress();
				export(PredicateFile.HFUNC_LOCAL_EP, addressString(f.getEntryPoint()), addressString(address));
			} else if (next instanceof FunctionSymbol fsym) {
				Reference[] references = fsym.getReferences();
				for (Reference r : references) {
					if (r instanceof ThunkReference || r instanceof ExternalReference) {
						Address address = r.getFromAddress();
						if (address != null) {
							export(PredicateFile.HFUNC_LOCAL_EP, addressString(f.getEntryPoint()),
									addressString(address));
						}
					}
				}
			}
		}
		HighFunction high = getHighFunction(res, f, decompiler);
		debug("Starting function " + high.getFunction().getName());

		// we want to make sure the pcode indexes are in source order.
		// we accomplish this by sorting the basic blocks topologically.
		GDirectedGraph<PcodeBlockBasicVertex, PcodeBlockBasicEdge> g = GraphFactory.createDirectedGraph();
		for (PcodeBlockBasic bb : high.getBasicBlocks()) {
			PcodeBlockBasicVertex v = new PcodeBlockBasicVertex(bb);
			g.addVertex(v);
			for (int i = 0; i < bb.getInSize(); i++) {
				PcodeBlockBasicVertex vIn = new PcodeBlockBasicVertex(bb.getIn(i));
				g.addVertex(vIn);
				g.addEdge(new PcodeBlockBasicEdge(vIn, v));
			}
			for (int i = 0; i < bb.getOutSize(); i++) {
				PcodeBlockBasicVertex vOut = new PcodeBlockBasicVertex(bb.getOut(i));
				g.addVertex(vOut);
				g.addEdge(new PcodeBlockBasicEdge(v, vOut));
			}
		}

		HashSet<PcodeOp> set = new HashSet<PcodeOp>();
		HashSet<Integer> bbset = new HashSet<Integer>();
		int index = 0;
		for (PcodeBlockBasicVertex v : DepthFirstSorter.preOrder(g)) {
			PcodeBlockBasic bb = v.bb();
			if (bbset.contains(bb.getIndex())) {
				continue;
			}
			bbset.add(bb.getIndex());
			debug("Starting basic block " + bb.getIndex());
			Iterator<PcodeOp> opiter = bb.getIterator(); // high.getPcodeOps();
			while (opiter.hasNext()) {
				PcodeOp op = opiter.next();
				if (op != null) {
					set.add(op);
					exportPcode(high, index++, op);
				}
			}
			debug("End basic block " + bb.getIndex());
		}

		exportPcodeOpSequence(high, set);
		exportHighFunction(high);
		debug("End function " + high.getFunction().getName());
	}

	private BigInteger readInteger(Program program, Address addr, int size) {
		//AddressFactory addrFactory = program.getAddressFactory();
		//int spaceID = addr.getAddressSpace().getSpaceID();
		try {
			byte[] dest = new byte[size];
			program.getMemory().getBytes(addr, dest, 0, size);
			if (!program.getLanguage().isBigEndian()) {
				reverseBytes(dest);
			}
			return new BigInteger(dest);
		} catch (MemoryAccessException e) {
			debug("MemoryAccessException, skipping: " + e);
			return BigInteger.ZERO;
		}
	}

	private void reverseBytes(byte[] arr) {
		for (int i = 0; i < arr.length / 2; i++) {
			byte tmp = arr[i];
			arr[i] = arr[arr.length - i - 1];
			arr[arr.length - i - 1] = tmp;
		}
	}

	public void processVTable(Program program, Symbol sym) {
		StringBuilder className = new StringBuilder();
		for (String s : sym.getPath()) {
			className.append("::" + s);
		}
		Address addr = sym.getAddress();
		if (program.getMemory().getBlock(addr).isExternalBlock())
			return;
		// SymbolTable symbolTable = program.getSymbolTable();
		AddressFactory addrFactory = program.getAddressFactory();
		int ptrBytes = program.getAddressFactory().getDefaultAddressSpace().getSize() / 8;

		// Skip first two addresses to get to function pointer table
		// BigInteger classOffset = readInteger(program, addr, ptrBytes);
		addr = addr.add(ptrBytes);
		// BigInteger typeInfo = readInteger(program, addr, ptrBytes);
		addr = addr.add(ptrBytes);
		Address tableAddr = addr;

		// Reads function pointer table
		int funOffset = 0;
		BigInteger funPtrInt;
		Address funPtrAddr;
		while (true) {
			// Breaks if we hit another vtable
			if (vtables.contains(addr))
				break;

			// read next function pointer
			funPtrInt = readInteger(program, addr, ptrBytes);
			funPtrAddr = addrFactory.getAddress(addrFactory.getDefaultAddressSpace().getSpaceID(),
					funPtrInt.longValue());

			// The table ends when one of three things is true:
			// 1. Reading a zero
			if (funPtrInt == BigInteger.ZERO)
				break;

			// 2. If there are defined symbols, we are out of the vtable, so break
			// if (symbolTable.getSymbols(funPtrAddr).length > 0)
			// break;

			// emit fact
			export(PredicateFile.VTABLE, className.toString(), addressString(tableAddr),
					Integer.toString(funOffset * ptrBytes), funPtrInt.toString());
			//
			// 3. if next block is different from ours, break
			if (program.getMemory().getBlock(funPtrAddr) == null
					|| program.getMemory().getBlock(funPtrAddr.add(ptrBytes)) == null)
				break;
			if (!program.getMemory().getBlock(funPtrAddr)
					.equals(program.getMemory().getBlock(funPtrAddr.add(ptrBytes))))
				break;

			addr = addr.add(ptrBytes);
			funOffset++;
		}
	}

	public void processVTables(Program program) {
		SymbolIterator vtableSymbols = program.getSymbolTable().getSymbols("vtable");
		while (vtableSymbols.hasNext()) {
			Symbol sym = vtableSymbols.next();
			processVTable(program, sym);
		}
	}

//	private void initializeSet(SymbolTable table) {
//		vtables.clear();
//		SymbolIterator iter = table.getSymbols("vtable");
//		while (iter.hasNext()) {
//			Symbol sym2 = iter.next();
//			vtables.add(sym2.getAddress());
//		}
//	}

	private HighFunction getHighFunction(DecompileResults res, Function func, DecompInterface decompiler) {
		HighFunction high = res.getHighFunction();
		if (high == null) {
			high = new HighFunction(func, decompiler.getLanguage(), decompiler.getCompilerSpec(),
					decompiler.getDataTypeManager());
			int default_extrapop = decompiler.getCompilerSpec().getDefaultCallingConvention().getExtrapop();
			high.grabFromFunction(default_extrapop, false, false);
			String id = funcID(func);
			export(PredicateFile.HFUNC_ISEXT, id);
		}
		return high;
	}

	private String addressString(Address addr) {
		return Long.toString(addr.getOffset());
	}

	private void export(PredicateFile pfile, String key) {
		db.add(pfile, key);
	}

	private void export(PredicateFile pfile, String key, String value) {
		db.add(pfile, key, value);
	}

	@SuppressWarnings("unused")
	private void export(PredicateFile pfile, String key, String val1, String val2) {
		db.add(pfile, key, val1, val2);
	}

	@SuppressWarnings("unused")
	private void export(PredicateFile pfile, String key, String val1, String val2, String val3) {
		db.add(pfile, key, val1, val2, val3);
	}

	private void exportL(PredicateFile pfile, String key, long value) {
		db.add(pfile, key, Long.toString(value));
	}

	private void exportN(PredicateFile label, String key, int index, String value) {
		if (value.equals("")) {
			db.add(label, key, Integer.toString(index));
		} else {
			db.add(label, key, Integer.toString(index), value);
		}
	}

	private void exportNL(PredicateFile label, String key, int index, long value) {
		db.add(label, key, Integer.toString(index), Long.toString(value));
	}

	private void exportPcode(HighFunction hfn, int index, PcodeOp op) {
		debug("<" + pcodeID(hfn, op) + "> [index: " + Integer.toString(index) + "]: " + op.toString());
		SequenceNumber sn = op.getSeqnum();
		String outstr = op.toString();
		String id = pcodeID(hfn, op);
		if (sn != null) {
			outstr = sn.getTarget() + SEP + String.valueOf(index) + SEP + sn.getTime();
			export(PredicateFile.PCODE_TIME, id, Integer.toString(sn.getTime()));
		}
		export(PredicateFile.PCODE_INDEX, id, String.valueOf(index));
		export(PredicateFile.PCODE_TOSTR, id, funcID(hfn.getFunction()) + SEP + outstr);
		export(PredicateFile.PCODE_MNEMONIC, id, op.getMnemonic());
		export(PredicateFile.PCODE_OPCODE, id, Integer.toString(op.getOpcode()));
		export(PredicateFile.PCODE_PARENT, id, bbID(hfn, op.getParent()));
		export(PredicateFile.PCODE_TARGET, id, addressString(op.getSeqnum().getTarget()));
		exportN(PredicateFile.PCODE_INPUT_COUNT, id, op.getNumInputs(), "");
		for (int i = 0; i < op.getNumInputs(); ++i) {
			VarnodeAST vni = (VarnodeAST) op.getInput(i);
			if (vni != null) {
				// OK, this is a little weird, but PTRSUBs with first arg == 0
				// are (usually) global variables at address == second arg
				if (op.getMnemonic().equals("PTRSUB") && (i == 0)) {
					if (vni.getAddress().getOffset() == 0) {
						VarnodeAST next = (VarnodeAST) op.getInput(1);
						HighVariable high = next.getHigh();
						if (high != null) {
							extraGlobals.put(high, next);
						}
					}
				}
				exportN(PredicateFile.PCODE_INPUT, id, i, vnodeID(hfn, vni));
				exportVarnode(hfn, vni);
				debug("  input " + i + ": " + vnodeID(hfn, vni));
			}
		}
		VarnodeAST vno = (VarnodeAST) op.getOutput();
		if (vno != null) {
			export(PredicateFile.PCODE_OUTPUT, id, vnodeID(hfn, vno));
			exportVarnode(hfn, vno);
			debug("  output: " + vnodeID(hfn, vno));
		}
	}

	private void exportVarnode(HighFunction hfn, VarnodeAST vn) {
		String id = vnodeID(hfn, vn);
		if (!varnodes.add(id))
			return;
		export(PredicateFile.VNODE_ADDRESS, id, addressString(vn.getAddress()));
		if (vn.isAddress()) {
			export(PredicateFile.VNODE_IS_ADDRESS, id);
		}
		if (vn.isAddrTied()) {
			export(PredicateFile.VNODE_IS_ADDRTIED, id);
		}
		export(PredicateFile.VNODE_PC_ADDRESS, id, addressString(vn.getPCAddress()));
		export(PredicateFile.VNODE_DESC, id, vn.toString());
		export(PredicateFile.VNODE_NAME, id, "vn" + String.valueOf(vn.getUniqueId()));
		long offset = vn.getOffset();
		export(PredicateFile.VNODE_OFFSET, id, Long.toHexString(offset));
		// if (offset < Long.MAX_VALUE && offset > Long.MIN_VALUE) {
		exportL(PredicateFile.VNODE_OFFSET_N, id, offset);
                export(PredicateFile.OFFSET_INDEX, String.valueOf(offset),
                    String.valueOf(offsets.getUniqueNumber(String.valueOf(offset))));
		// }
		export(PredicateFile.VNODE_SIZE, id, Integer.toString(vn.getSize()));
		export(PredicateFile.VNODE_SPACE, id, vn.getAddress().getAddressSpace().getName());
		export(PredicateFile.VNODE_HFUNC, id, hfuncID(hfn));
		HighVariable hv = vn.getHigh();
		if (hv == null) {
			// export("VNODE_TOSTR", id, funcID(hfn.getFunction())+SEP+vn.toString());
			export(PredicateFile.VNODE_TOSTR, id,
					funcID(hfn.getFunction()) + SEP + vn.getPCAddress().toString() + SEP + vn.toString());
		} else {
			if (hv instanceof HighConstant && hv.getDataType() instanceof Pointer) {
				if (offset != 0) {
					extraGlobals.put(hv, vn);
				}
			}
			// export("VNODE_TOSTR", id, funcID(hfn.getFunction())+hvarName(hfn,hv));
			export(PredicateFile.VNODE_TOSTR, id,
					funcID(hfn.getFunction()) + SEP + vn.getPCAddress().toString() + SEP + hvarName(hfn, hv));
			export(PredicateFile.VNODE_HVAR, id, hvarID(hfn, hv));
			exportHighVariable(hfn, hv, true);
		}
		if (vn.getDef() != null) {
			export(PredicateFile.VNODE_DEF, id, pcodeID(hfn, vn.getDef()));
		}
	}

	private void exportHighVariable(HighFunction hfn, HighVariable hv, boolean dontDescend) {
		String id = hvarID(hfn, hv);
		export(PredicateFile.HVAR_NAME, id, hvarName(hfn, hv));
		export(PredicateFile.HVAR_SIZE, id, Integer.toString(hv.getSize()));
		if (hv instanceof HighGlobal) {
			export(PredicateFile.HVAR_CLASS, id, "global");
		}
		if (hv instanceof HighLocal) {
			export(PredicateFile.HVAR_CLASS, id, "local");
			Address pcAddress = ((HighLocal) hv).getPCAddress();
			if (pcAddress != null) {
				export(PredicateFile.HVAR_SCOPE, id, addressString(pcAddress));
			}
		}
		if (hv instanceof HighConstant) {
			export(PredicateFile.HVAR_CLASS, id, "constant");
		}
		if (hv instanceof HighOther) {
			export(PredicateFile.HVAR_CLASS, id, "other");
		}
		DataType dataType = hv.getDataType();
		if (dataType != null) {
			export(PredicateFile.HVAR_TYPE, id, dtID(dataType));
			exportType(dataType);
		}
		if (hv.getSymbol() != null) {
			String hsid = hsID(hfn, hv.getSymbol());
			export(PredicateFile.SYMBOL_HVAR, hsid, hvarID(hfn, hv));
//			HighSymbol hs = hv.getSymbol();
//			if (hs != null) {
//				export(PredicateFile.HVAR_NAME, id, hs.getName());
//			}
		}
		if (!dontDescend) {
			VarnodeAST representative = (VarnodeAST) hv.getRepresentative();
			if (representative != null) {
				export(PredicateFile.HVAR_REPRESENTATIVE, id, vnodeID(hfn, representative));
				exportVarnode(hfn, representative);
			}
			Varnode[] instances = hv.getInstances();
			for (Varnode varnode : instances) {
				exportVarnode(hfn, (VarnodeAST) varnode);
			}
		}
	}

	private void exportType(DataType dataType) {
		String id = dtID(dataType);
		if (!types.add(id))
			return;

		export(PredicateFile.TYPE_NAME, id, id);
		exportN(PredicateFile.TYPE_LENGTH, id, dataType.getLength(), "");
		while (dataType instanceof TypeDef) {
			TypeDef typedef = (TypeDef) dataType;
			dataType = typedef.getBaseDataType();
		}
		if (dataType instanceof Pointer) {
			export(PredicateFile.TYPE_POINTER, id);
			DataType baseType = ((Pointer) dataType).getDataType();
			if (baseType != null) {
				export(PredicateFile.TYPE_POINTER_BASE, id, dtID(baseType));
				exportType(baseType);
			}
			// else {
			// System.err.println("TEST");
			// }
		}
		if (dataType instanceof Array) {
			export(PredicateFile.TYPE_ARRAY, id);
			Array arr = (Array) dataType;
			export(PredicateFile.TYPE_ARRAY_BASE, id, dtID(arr.getDataType()));
			exportN(PredicateFile.TYPE_ARRAY_N, id, arr.getNumElements(), "");
			exportN(PredicateFile.TYPE_ARRAY_ELEMENT_LENGTH, id, arr.getElementLength(), "");
			exportType(arr.getDataType());
		}
		if (dataType instanceof Structure) {
			export(PredicateFile.TYPE_STRUCT, id);
			Structure struct = (Structure) dataType;
			exportN(PredicateFile.TYPE_STRUCT_FIELD_COUNT, id, struct.getNumComponents(), "");
			for (int i = 0; i < struct.getNumComponents(); i++) {
				DataTypeComponent dtc = struct.getComponent(i);
				exportComponent("TYPE_STRUCT", id, i, dtc);
			}
		}
		if (dataType instanceof Union) {
			export(PredicateFile.TYPE_UNION, id);
			Union union = (Union) dataType;
			exportN(PredicateFile.TYPE_UNION_FIELD_COUNT, id, union.getNumComponents(), "");
			for (int i = 0; i < union.getNumComponents(); i++) {
				DataTypeComponent dtc = union.getComponent(i);
				exportComponent("TYPE_UNION", id, i, dtc);
			}
		}
		if (dataType instanceof FunctionDefinition) {
			export(PredicateFile.TYPE_FUNC, id);
			FunctionDefinition fd = (FunctionDefinition) dataType;
			export(PredicateFile.TYPE_FUNC_RET, id, fd.getReturnType().toString());
			exportType(fd.getReturnType());
			if (fd.hasVarArgs()) {
				export(PredicateFile.TYPE_FUNC_VARARGS, id);
			}
			ParameterDefinition[] arguments = fd.getArguments();
			exportN(PredicateFile.TYPE_FUNC_PARAM_COUNT, id, arguments.length, "");
			for (int i = 0; i < arguments.length; i++) {
				exportN(PredicateFile.TYPE_FUNC_PARAM, id, i, arguments[i].toString());
				exportType(arguments[i].getDataType());
			}
		}
		if (dataType instanceof BooleanDataType) {
			export(PredicateFile.TYPE_BOOLEAN, id);
		}
		if (dataType instanceof AbstractIntegerDataType) {
			export(PredicateFile.TYPE_INTEGER, id);
		}
		if (dataType instanceof AbstractFloatDataType) {
			export(PredicateFile.TYPE_FLOAT, id);
		}
		if (dataType instanceof Enum) {
			export(PredicateFile.TYPE_ENUM, id);
		}
	}

	private void exportComponent(String label, String id, int i, DataTypeComponent dtc) {
		String dtcid = dtID(dtc.getDataType());
		exportN(componentPredicates.get(label + "_FIELD"), id, i, dtcid);
		exportNL(componentPredicates.get(label + "_OFFSET"), id, i, dtc.getOffset());
		exportNL(componentPredicates.get(label + "_OFFSET_N"), id, i, dtc.getOffset());
		if (dtc.getFieldName() != null && !dtc.getFieldName().isEmpty()) {
			exportN(componentPredicates.get(label + "_FIELD_NAME"), id, i, dtc.getFieldName());
			exportN(componentPredicates.get(label + "_FIELD_NAME_BY_OFFSET"), id, dtc.getOffset(), dtc.getFieldName());
		}
		exportType(dtc.getDataType());
	}

	boolean isString(String mnemonic) {
		if (mnemonic.equals(new String("ds")) || mnemonic.equals(new String("unicode"))
				|| mnemonic.equals(new String("p_unicode")) || mnemonic.equals(new String("p_string"))
				|| mnemonic.equals(new String("p_string255")) || mnemonic.equals(new String("mbcs"))) {
			return true;
		}
		return false;
	}

	private void exportHighFunction(HighFunction hfn) {
		Function f = hfn.getFunction();

		for (PcodeBlockBasic bb : hfn.getBasicBlocks()) {
			String bbid = bbID(hfn, bb);
			export(PredicateFile.BB_HFUNC, bbid, hfuncID(hfn));
			if (bb.getStart() != null) {
				export(PredicateFile.BB_START, bbid, addressString(bb.getStart()));
			}
			for (int i = 0; i < bb.getInSize(); i++) {
				export(PredicateFile.BB_IN, bbid, bbID(hfn, bb.getIn(i)));
			}
			for (int i = 0; i < bb.getOutSize(); i++) {
				export(PredicateFile.BB_OUT, bbid, bbID(hfn, bb.getOut(i)));
			}
			if (bb.getOutSize() > 1) {
				export(PredicateFile.BB_TOUT, bbid, bbID(hfn, bb.getTrueOut()));
				export(PredicateFile.BB_FOUT, bbid, bbID(hfn, bb.getFalseOut()));
			}
		}
		String id = hfuncID(hfn);
		export(PredicateFile.HFUNC_NAME, id, hfn.getFunction().getName());
		export(PredicateFile.HFUNC_FUNC, id, funcID(hfn.getFunction()));
		export(PredicateFile.HFUNC_TOSTR, id, funcID(hfn.getFunction()));
		export(PredicateFile.HFUNC_CSPEC, id, hfn.getCompilerSpec().toString());
		export(PredicateFile.HFUNC_LANG, id, hfn.getLanguage().toString());
		export(PredicateFile.HFUNC_EP, id, addressString(hfn.getFunction().getEntryPoint()));
		FunctionPrototype proto = hfn.getFunctionPrototype();
		if (proto != null) {
			export(PredicateFile.HFUNC_PROTO, id, funcID(hfn.getFunction()));
			exportPrototype(hfn, proto, funcID(hfn.getFunction()));
		}
		Function thunk = f.getThunkedFunction(false);
		if (thunk != null && thunk.isExternal()) {
			export(PredicateFile.HFUNC_ISEXT, id);
		}
		export(PredicateFile.HFUNC_ISEP, id);

		Iterator<HighSymbol> symbols = hfn.getLocalSymbolMap().getSymbols();
		while (symbols.hasNext()) {
			HighSymbol hs = symbols.next();
			String hsid = hsID(hfn, hs);
			export(PredicateFile.SYMBOL_HFUNC, hsid, id);
			export(PredicateFile.SYMBOL_NAME, hsid, hs.getName());
			HighVariable hv = hs.getHighVariable();
			if (hv != null) {
				export(PredicateFile.SYMBOL_HVAR, hsid, hvarID(hfn, hv));
				exportHighVariable(hfn, hv, false);
			}
		}
	}

	public void exportDefinedData(Program p) {
		DataIterator dataIter = p.getListing().getDefinedData(p.getMinAddress(), true);
		for (Data d : dataIter) {
			if (!isString(d.getMnemonicString()))
				continue;
			Address addr = d.getAddress();
			export(PredicateFile.DATA_STRING, addressString(addr), d.getValue().toString());
		}
	}

	private void exportPrototype(HighFunction hfn, FunctionPrototype proto, String id) {
		exportN(PredicateFile.PROTO_PARAMETER_COUNT, id, proto.getNumParams(), "");
		for (int i = 0; i < proto.getNumParams(); i++) {
			HighSymbol param = proto.getParam(i);
			String hsid = hsID(hfn, param);
			HighVariable pvar = param.getHighVariable();
			if (pvar != null) {
				exportHighVariable(hfn, pvar, true);
				export(PredicateFile.SYMBOL_HVAR, hsid, hvarID(hfn, pvar));
				VarnodeAST rep = (VarnodeAST) pvar.getRepresentative();
				export(PredicateFile.HVAR_REPRESENTATIVE, hvarID(hfn, pvar), vnodeID(hfn, rep));
				exportVarnode(hfn, rep);
			} else {
				// fake out a HighVar
				String vnid = hsid + SEP + "0";
				export(PredicateFile.HVAR_NAME, hsid, param.getName());
				export(PredicateFile.SYMBOL_HVAR, hsid, hsid);
				export(PredicateFile.SYMBOL_NAME, hsid, param.getName());
				export(PredicateFile.HVAR_REPRESENTATIVE, hsid, vnid);
				export(PredicateFile.VNODE_HVAR, vnid, hsid);
				export(PredicateFile.VNODE_HFUNC, vnid, hfuncID(param.getHighFunction()));
				export(PredicateFile.VNODE_SPACE, vnid, "fake");
				export(PredicateFile.VNODE_NAME, vnid, param.getName() + SEP + "0");
			}
			exportN(PredicateFile.PROTO_PARAMETER, id, i, hsid);
			export(PredicateFile.PROTO_PARAMETER_DATATYPE, hsid, dtID(param.getDataType()));
			exportType(param.getDataType());
		}
		/*
		 * ParameterDefinition[] parameterDefinitions = proto.getParameterDefinitions();
		 * if (parameterDefinitions != null) { for (ParameterDefinition def :
		 * parameterDefinitions) { exportN("PROTO_PARAMETER_DEFINITION", id,
		 * def.getOrdinal(), def.getName()); export("PROTO_PARAMETER_DATATYPE",
		 * def.getName(), dtID(def.getDataType())); exportType(def.getDataType()); } }
		 */
		DataType returnType = proto.getReturnType();
		if (returnType != null) {
			export(PredicateFile.PROTO_RETTYPE, id, dtID(returnType));
			exportType(returnType);
		}
		export(PredicateFile.PROTO_CALLING_CONVENTION, id, hfn.getFunction().getCallingConventionName());
		if (proto.hasNoReturn())
			export(PredicateFile.PROTO_IS_VOID, id);
		if (proto.hasThisPointer())
			export(PredicateFile.PROTO_HAS_THIS, id);
		if (proto.isVarArg())
			export(PredicateFile.PROTO_IS_VARARG, id);
		if (proto.isInline())
			export(PredicateFile.PROTO_IS_INLINE, id);
		if (proto.isConstructor())
			export(PredicateFile.PROTO_IS_CONSTRUCTOR, id);
		if (proto.isDestructor())
			export(PredicateFile.PROTO_IS_DESTRUCTOR, id);
	}

	private void exportPcodeOpSequence(HighFunction hfn, HashSet<PcodeOp> set) {
		Iterator<PcodeOpAST> opiter = hfn.getPcodeOps();
		HashSet<PcodeBlockBasic> seenParents = new HashSet<PcodeBlockBasic>();
		HashMap<PcodeBlock, PcodeOp> first = new HashMap<PcodeBlock, PcodeOp>();
		HashMap<PcodeBlock, PcodeOp> last = new HashMap<PcodeBlock, PcodeOp>();
		while (opiter.hasNext()) {
			PcodeOpAST op = opiter.next();
			PcodeBlockBasic parent = op.getParent();
			if (seenParents.contains(parent)) {
				continue;
			}
			Iterator<PcodeOp> iterator = parent.getIterator();
			PcodeOp prev = null;
			PcodeOp next = null;
			while (iterator.hasNext()) {
				next = iterator.next();
				if (prev == null && set.contains(next)) {
					first.put(parent, next);
				}
				if (prev != null && set.contains(prev) && set.contains(next)) {
					export(PredicateFile.PCODE_NEXT, pcodeID(hfn, prev), pcodeID(hfn, next));
				}
				prev = next;
			}
			if (next != null && set.contains(next)) {
				last.put(parent, next);
			}
			seenParents.add(parent);
		}
		for (PcodeBlock block : first.keySet()) {
			PcodeOpAST ast = (PcodeOpAST) first.get((block));
			export(PredicateFile.BB_FIRST, bbID(hfn, block), pcodeID(hfn, ast));
		}
		for (PcodeBlock block : last.keySet()) {
			export(PredicateFile.BB_LAST, bbID(hfn, block), pcodeID(hfn, last.get(block)));
		}
	}

	private String pcodeID(HighFunction hfn, PcodeOp op) {
		SequenceNumber sn = op.getSeqnum();
		if (sn != null) {
			return hfuncID(hfn) + SEP + sn.getTarget() + SEP + sn.getTime();
		}
		return hfuncID(hfn) + SEP + "NO_SEQNUM" + SEP + op.toString();
	}

	private String vnodeID(HighFunction hfn, VarnodeAST vn) {
		return hfuncID(hfn) + SEP + Integer.toString(vn.getUniqueId());
	}

	private String hvarID(HighFunction hfn, HighVariable hv) {
		return hfuncID(hfn) + SEP + hvarName(hfn, hv);
	}

	private String hvarName(HighFunction hf, HighVariable hv) {
		Varnode rep = hv.getRepresentative();
		if (rep.getAddress().isUniqueAddress()) {
			DynamicHash dynamicHash = new DynamicHash(rep, hf);
			return "hv"+Long.toString(dynamicHash.getHash());
		}
		if (hv.getName() == null || hv.getName().equals("UNNAMED")) {
			if (hv instanceof HighConstant || hv instanceof HighOther) {
				Address addr = rep.getAddress();
				return addr.toString();
			}
			if (hv instanceof HighLocal) {
				Address addr = rep.getAddress();
				return addr.toString();
			}
			if (hv instanceof HighGlobal) {
				SymbolTable symbolTable = hf.getFunction().getProgram().getSymbolTable();
				Address addr = rep.getAddress();
				if (extraGlobals.containsKey(hv)) {
					VarnodeAST vn = extraGlobals.get(hv);
					addr = addr.getNewAddress(vn.getOffset());
				}
				Symbol symbol = symbolTable.getPrimarySymbol(addr);
				if (symbol != null) {
					export(PredicateFile.HVAR_CLASS, hfuncID(hf) + SEP + symbol.getName(), "global");
					return symbol.getName();
				}
				return addr.toString();
			}
			return null;
		}
		return hv.getName();
	}

	private String hsID(HighFunction hfn, HighSymbol hs) {
		return hfuncID(hfn) + SEP + hs.getName();
	}

	public String funcID(Function fn) {
		return fn.getName(true) + "@" + fn.getEntryPoint();
	}

	public String hfuncID(HighFunction fn) {
		Function f = fn.getFunction();
		return funcID(f);
	}

	private String bbID(HighFunction hfn, PcodeBlock bb) {
		if (bb.getStart() != null) {
			return hfuncID(hfn) + SEP + bb.hashCode();
		}
		return hfuncID(hfn) + SEP + "unknown block";
	}

	private String dtID(DataType dt) {
		if (dt.getName() != null) {
			return dt.getName().replaceAll(" ", "");
		}
		return dt.toString();
	}

	private void debug(String s) {
		try {
			this.debug.write(s);
			this.debug.write('\n');
		} catch (IOException e) {
			throw new RuntimeException(e.toString());
		}
		// db.add(PredicateFile.PcodeOps, s);
	}
}

//class ResultWriter implements Runnable {
//	BlockingQueue<DecompileResults> q = new ArrayBlockingQueue<>(50);
//	
//	HighFunctionExporter ex;
//	DecompilerConfigurer configurer;
//	
//	boolean shutDown = false;
//
//	private TaskMonitor monitor;
//	
//	public ResultWriter(HighFunctionExporter ex, DecompilerConfigurer configurer, TaskMonitor tMonitor) {
//		this.ex = ex;
//		this.configurer = configurer;
//		this.monitor = tMonitor;
//	}
//	
//	BlockingQueue<DecompileResults> getQueue() {
//		return q;
//	}
//
//	@Override
//	public void run() {
//        try {
//        	int count = 0;
//            while(!(shutDown && q.isEmpty())){
//            	monitor.checkCancelled();
//            	DecompileResults results = q.take();
//
//            	ex.processFunction(results, results.getFunction(), configurer.getInteface());
//            	
//            	count++;
//            	if (count > 50) {
//                  ex.writeFacts();
//            		count = 0;
//            	}
//            }
//        } catch (InterruptedException | IOException | CancelledException e) {}
//	}
//	
//	public void done() {
//		shutDown = true;
//	}
//}

public class ExportPCodeForCTADL extends GhidraScript {

	File outputDirectory;
	boolean DEBUG = false;

	@Override
	protected void run() throws Exception {

		String[] args = getScriptArgs();
		PluginTool tool = state.getTool();
		if (tool == null) {
			println("Script is not running in GUI");
		}
		if (args.length >= 1) {
			outputDirectory = new File(args[0]);
		} else {
			outputDirectory = askDirectory("Select Directory for Results", "OK");
		}

		// System.setProperty("cpu.core.override", "10");
		// String cpuOverrideString = System.getProperty("cpu.core.override");
		long startTime = System.nanoTime();
		// GThreadPool threadPool = GThreadPool.getSharedThreadPool("Parallel
		// Decompiler");

		HighFunctionExporter ex = new HighFunctionExporter(outputDirectory.getAbsolutePath());
		ex.getDatabase().add(PredicateFile.LANGUAGE, "PCODE");
		ex.getDatabase().add(PredicateFile.PROGRAM_FILE, getProgramFile().toString());

		DecompilerConfigurer configurer = new DecompilerConfigurer(currentProgram);

		DecompilerCallback<DecompileResults> callback = new DecompilerCallback<DecompileResults>(currentProgram,
				configurer) {
			int count = 0;

			@Override
			// This could be done better, when results are available, other decompiler
			// results will stall.
			public synchronized DecompileResults process(DecompileResults results, TaskMonitor tMonitor)
					throws Exception {
				// This routine could pass the results to another thread's queue to add to the
				// DB
				// then there is only one DB writer and no synchronization needed. Decompiler
				// threads can go as fast as they can without waiting for writing.
				// With the chunking method, all decompiler threads would stall until the write
				// was finished and a new chunk of functions could be gotten.
				ex.processFunction(results, results.getFunction(), configurer.getInteface());
				count++;
				if (count > 20) {
					ex.writeFacts(false);
					count = 0;
				}
				return null;
			}
		};

		Set<Function> toProcess = new HashSet<Function>();
		currentProgram.getFunctionManager().getFunctions(true).forEach(f -> {
			toProcess.add(f);
		});
		currentProgram.getFunctionManager().getExternalFunctions().forEach(f -> {
			toProcess.add(f);
		});
		List<Function> toProcessList = new ArrayList<Function>(toProcess);

		Collections.sort(toProcessList,
				(o1, o2) -> -Long.compare(o1.getBody().getNumAddresses(), o2.getBody().getNumAddresses()));

		monitor.initialize(toProcess.size());

		// dump defined data once
		ex.exportDefinedData(currentProgram);
		ex.writeFacts(true);

		ParallelDecompiler.decompileFunctions(callback, toProcessList, monitor);

		// System.out.println("Done producing");

		ex.processVTables(currentProgram);
		// waiting until the end to write all datatypes TYPE_ may not save much time.
		// It could save time if the structures are complicated, so constantly
		// traversing
		// structure references all over again every 50 functions. Might not be worth
		// it.
		ex.writeFacts(true);
		ex.writeDebug();

		long endTime = System.nanoTime();
		long duration = (endTime - startTime) / 1000000;
		println("total duration: " + Long.toString(duration));
	}

}
