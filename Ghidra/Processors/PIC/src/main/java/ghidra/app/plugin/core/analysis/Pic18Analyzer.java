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
package ghidra.app.plugin.core.analysis;

import java.util.*;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.graph.*;
import ghidra.util.task.TaskMonitor;

public class Pic18Analyzer extends AbstractAnalyzer {
	private static final String NAME = "PIC-18";
	private static final String DESCRIPTION = "Analyzes PIC-18 instructions.";

	//private static final int INSTRUCTION_LENGTH = 2;
	private static final long RESET_VECTOR_OFFSET = 0;
	private static final long HIGH_INTERRUPT_VECTOR_OFFSET = 0x8;
	private static final long LOW_INTERRUPT_VECTOR_OFFSET = 0x18;

	//private static final Character DEST_W = 'w';
	private static final Character DEST_FREG = 'f';

	//private static final String PIC18_LANG = "Sleigh-PIC-18";

	private static final String CODE_SPACE_NAME = "CODE";

	private static final HashSet<String> REG_MODIFICATION_MNEMONICS = new HashSet<String>();
	static {
		REG_MODIFICATION_MNEMONICS.add("ADDWF");
		REG_MODIFICATION_MNEMONICS.add("ADDWFC");
		REG_MODIFICATION_MNEMONICS.add("ANDWF");
		REG_MODIFICATION_MNEMONICS.add("CLRF");  // always changes f
		REG_MODIFICATION_MNEMONICS.add("COMF");
		REG_MODIFICATION_MNEMONICS.add("DECF");
		REG_MODIFICATION_MNEMONICS.add("DECFSZ");
		REG_MODIFICATION_MNEMONICS.add("DCFSNZ");
		REG_MODIFICATION_MNEMONICS.add("INCF");
		REG_MODIFICATION_MNEMONICS.add("INCFSZ");
		REG_MODIFICATION_MNEMONICS.add("INFSNZ");
		REG_MODIFICATION_MNEMONICS.add("IORWF");
		REG_MODIFICATION_MNEMONICS.add("MOVWF"); // always changes f
		REG_MODIFICATION_MNEMONICS.add("NEGF");  // always changes f
		REG_MODIFICATION_MNEMONICS.add("RLCF");
		REG_MODIFICATION_MNEMONICS.add("RLNCF");
		REG_MODIFICATION_MNEMONICS.add("RRCF");
		REG_MODIFICATION_MNEMONICS.add("RRNCF");
		REG_MODIFICATION_MNEMONICS.add("SETF");  // always changes f
		REG_MODIFICATION_MNEMONICS.add("SUBFWB");
		REG_MODIFICATION_MNEMONICS.add("SUBWF");
		REG_MODIFICATION_MNEMONICS.add("SUBWFB");
		REG_MODIFICATION_MNEMONICS.add("SWAPF");
		REG_MODIFICATION_MNEMONICS.add("XORWF");
	}

	private static final HashSet<String> FREG_INSTRUCTIONS = new HashSet<String>();
	static {
		FREG_INSTRUCTIONS.add("ADDWF");
		FREG_INSTRUCTIONS.add("ADDWFC");
		FREG_INSTRUCTIONS.add("ANDWF");
		FREG_INSTRUCTIONS.add("CLRF");
		FREG_INSTRUCTIONS.add("COMF");
		FREG_INSTRUCTIONS.add("DECF");
		FREG_INSTRUCTIONS.add("DECFSZ");
		FREG_INSTRUCTIONS.add("DCFSNZ");
		FREG_INSTRUCTIONS.add("INCF");
		FREG_INSTRUCTIONS.add("INCFSZ");
		FREG_INSTRUCTIONS.add("INFSNZ");
		FREG_INSTRUCTIONS.add("IORWF");
		FREG_INSTRUCTIONS.add("LFSR");
		FREG_INSTRUCTIONS.add("MOVF");
		FREG_INSTRUCTIONS.add("MOVWF");
		FREG_INSTRUCTIONS.add("NEGF");
		FREG_INSTRUCTIONS.add("RLCF");
		FREG_INSTRUCTIONS.add("RLNCF");
		FREG_INSTRUCTIONS.add("RRCF");
		FREG_INSTRUCTIONS.add("RRNCF");
		FREG_INSTRUCTIONS.add("SETF");
		FREG_INSTRUCTIONS.add("SUBFWB");
		FREG_INSTRUCTIONS.add("SUBWF");
		FREG_INSTRUCTIONS.add("SUBWFB");
		FREG_INSTRUCTIONS.add("SWAPF");
		FREG_INSTRUCTIONS.add("TSTFSZ");
		FREG_INSTRUCTIONS.add("XORWF");
	}

	private static final HashSet<String> FREG_BIT_INSTRUCTIONS = new HashSet<String>();
	static {
		FREG_BIT_INSTRUCTIONS.add("BCF");
		FREG_BIT_INSTRUCTIONS.add("BSF");
		FREG_BIT_INSTRUCTIONS.add("BTG");
		FREG_BIT_INSTRUCTIONS.add("BTFSC");
		FREG_BIT_INSTRUCTIONS.add("BTFSS");
	}

	private static final HashSet<String> SKIP_INSTRUCTIONS = new HashSet<String>();
	static {
		SKIP_INSTRUCTIONS.add("CPFSEQ");
		SKIP_INSTRUCTIONS.add("CPFSGT");
		SKIP_INSTRUCTIONS.add("CPFSLT");
		SKIP_INSTRUCTIONS.add("DECFSZ");
		SKIP_INSTRUCTIONS.add("DCFSNZ");
		SKIP_INSTRUCTIONS.add("INCFSZ");
		SKIP_INSTRUCTIONS.add("INFSNZ");
		SKIP_INSTRUCTIONS.add("TSTFSZ");
		SKIP_INSTRUCTIONS.add("BTFSC");
		SKIP_INSTRUCTIONS.add("BTFSS");
	}

	// RegName -> String[] { bit names }
	private static final HashMap<String, String[]> FREG_BIT_NAMES_MAP =
		new HashMap<String, String[]>();
	static {
		FREG_BIT_NAMES_MAP.put("STKPTR",
			new String[] { "SP0", "SP1", "SP2", "SP3", "SP4", null, "STKUNF", "STKFUL" });
		FREG_BIT_NAMES_MAP.put("INTCON",
			new String[] { "RBIF", "INT0IF", "TMR0IF", "RBIE", "INT0IE", "TMR0IE" });
		FREG_BIT_NAMES_MAP.put("INTCON2",
			new String[] { "RBIP", null, "TMR0IP", null, "INTEDG2", "INTEDG1", "INTEDG0", "RBPU" });
		FREG_BIT_NAMES_MAP.put("INTCON3", new String[] { "INT1IF", "INT2IF", null, "INT1IE",
			"INT2IE", null, "INT1IP", "INT2IP" });
		FREG_BIT_NAMES_MAP.put("STATUS", new String[] { "C", "DC", "Z", "OV", "N" });
		FREG_BIT_NAMES_MAP.put("T0CON",
			new String[] { "T0PS0", "T0PS1", "T0PS2", "PSA", "T0SE", "T0CS", "T08BIT", "TMR0ON" });
		FREG_BIT_NAMES_MAP.put("OSCCON", new String[] { "SCS" });
		FREG_BIT_NAMES_MAP.put("LVDCON",
			new String[] { "LVDL0", "LVDL1", "LVDL2", "LVDL3", "LVDEN", "IRVST" });
		FREG_BIT_NAMES_MAP.put("WDTCON", new String[] { "SWDTE" });
		FREG_BIT_NAMES_MAP.put("RCON",
			new String[] { "!BOR", "!POR", "!PD", "!TO", "!RI", null, "LWRT", "IPEN" });
		FREG_BIT_NAMES_MAP.put("T1CON", new String[] { "TMR1ON", "TMR1CS", "T1SYNC", "T1OSCEN",
			"T1CKPS0", "T1CKPS1", null, "RD16" });
		FREG_BIT_NAMES_MAP.put("T2CON", new String[] { "T2CKPS0", "T2CKPS1", "TMR2ON", "T2OUTPS0",
			"T2OUTPS1", "T2OUTPS2", "T2OUTPS3" });
		FREG_BIT_NAMES_MAP.put("SSPSTAT",
			new String[] { "BF", "UA", "R!W", "S", "P", "D!A", "CKE", "SMP" });
		FREG_BIT_NAMES_MAP.put("SSPCON1",
			new String[] { "SSPM0", "SSPM1", "SSPM2", "SSPM3", "CKP", "SSPEN", "SSPOV", "WCOL" });
		FREG_BIT_NAMES_MAP.put("SSPCON2",
			new String[] { "SEN", "RSEN", "PEN", "RCEN", "ACKEN", "ACKDT", "ACKSTAT", "GCEN" });
		FREG_BIT_NAMES_MAP.put("ADCON0",
			new String[] { "ADON", null, "GO!DONE", "CHS0", "CHS1", "CHS2", "ADCS0", "ADCS1" });
		FREG_BIT_NAMES_MAP.put("ADCON1",
			new String[] { "PCFG0", "PCFG1", "PCFG2", "PCFG3", null, null, "ADCS2", "ADFM" });
		FREG_BIT_NAMES_MAP.put("ADCON2",
			new String[] { "ADCS0", "ADCS1", "ADCS2", null, null, null, null, "ADFM" });
		FREG_BIT_NAMES_MAP.put("CCP1CON",
			new String[] { "CCP1M0", "CCP1M1", "CCP1M2", "CCP1M3", "DC1B0", "DC1B1" });
		FREG_BIT_NAMES_MAP.put("CCP2CON",
			new String[] { "CCP2M0", "CCP2M1", "CCP2M2", "CCP2M3", "DC2B0", "DC2B1" });
		FREG_BIT_NAMES_MAP.put("CCP3CON",
			new String[] { "CCP3M0", "CCP3M1", "CCP3M2", "CCP3M3", "DC3B0", "DC3B1" });
		FREG_BIT_NAMES_MAP.put("CVRCON",
			new String[] { "CVR0", "CVR1", "CVR2", "CVR3", "CVRSS", "CVRR", "CVROE", "CVREN" });
		FREG_BIT_NAMES_MAP.put("CMCON",
			new String[] { "CM0", "CM1", "CM2", "CIS", "C1INV", "C2INV", "C1OUT", "C2OUT" });
		FREG_BIT_NAMES_MAP.put("T3CON", new String[] { "TMR3ON", "TMR3CS", "T3SYNC", "T3CCP1",
			"T3CKPS0", "T3CKPS1", "T3CCP2", "RD16" });
		FREG_BIT_NAMES_MAP.put("PSPCON",
			new String[] { null, null, null, null, "PSPMODE", "IBOV", "OBF", "IBF" });
		FREG_BIT_NAMES_MAP.put("TXSTA1",
			new String[] { "TX9D", "TRMT", "BRGH", null, "SYNC", "TXEN", "TX9", "CSRC" });
		FREG_BIT_NAMES_MAP.put("RCSTA1",
			new String[] { "RX9D", "OERR", "FERR", "ADDEN", "CREN", "SREN", "RX9", "SPEN" });
		FREG_BIT_NAMES_MAP.put("EECON1",
			new String[] { "RD", "WR", "WREN", "WRERR", "FREE", null, "CFGS", "EEPGD" });
		FREG_BIT_NAMES_MAP.put("IPR3",
			new String[] { "CCP3IP", "CCP4IP", "CCP5IP", "TMR4IP", "TX2IP", "RC2IP" });
		FREG_BIT_NAMES_MAP.put("PIR3",
			new String[] { "CCP3IF", "CCP4IF", "CCP5IF", "TMR4IF", "TX2IF", "RC2IF" });
		FREG_BIT_NAMES_MAP.put("PIE3",
			new String[] { "CCP3IE", "CCP4IE", "CCP5IE", "TMR4IE", "TX2IE", "RC2IE" });
		FREG_BIT_NAMES_MAP.put("IPR2",
			new String[] { "CCP2IP", "TMR3IP", "LVDIP", "BCLIP", "EEIP", null, "CMIP" });
		FREG_BIT_NAMES_MAP.put("PIR2",
			new String[] { "CCP2IF", "TMR3IF", "LVDIF", "BCLIF", "EEIF", null, "CMIF" });
		FREG_BIT_NAMES_MAP.put("PIE2",
			new String[] { "CCP2IE", "TMR3IE", "LVDIE", "BCLIE", "EEIE", null, "CMIE" });
		FREG_BIT_NAMES_MAP.put("IPR1", new String[] { "TMR1IP", "TMR2IP", "CCP1IP", "SSPIP", "TXIP",
			"RCIP", "ADIP", "PSPIP" });
		FREG_BIT_NAMES_MAP.put("PIR1", new String[] { "TMR1IF", "TMR2IF", "CCP1IF", "SSPIF", "TXIF",
			"RCIF", "ADIF", "PSPIF" });
		FREG_BIT_NAMES_MAP.put("PIE1", new String[] { "TMR1IE", "TMR2IE", "CCP1IE", "SSPIE", "TXIE",
			"RCIE", "ADIE", "PSPIE" });
		FREG_BIT_NAMES_MAP.put("MEMCON",
			new String[] { "WM0", "WM1", null, null, "WAIT0", "WAIT1", null, "EBDIS" });
		FREG_BIT_NAMES_MAP.put("T4CON", new String[] { "T4CKPS0", "T4CKPS1", "TMR4ON", "T4OUTPS0",
			"T4OUTPS1", "T4OUTPS2", "T4OUTPS3" });
		FREG_BIT_NAMES_MAP.put("CCP4CON",
			new String[] { "CCP4M0", "CCP4M1", "CCP4M2", "CCP4M3", "DC4B0", "DC4B1" });
		FREG_BIT_NAMES_MAP.put("CCP5CON",
			new String[] { "CCP5M0", "CCP5M1", "CCP5M2", "CCP5M3", "DC5B0", "DC5B1" });
		FREG_BIT_NAMES_MAP.put("TXSTA2",
			new String[] { "TX9D", "TRMT", "BRGH", null, "SYNC", "TXEN", "TX9", "CSRC" });
		FREG_BIT_NAMES_MAP.put("RCSTA2",
			new String[] { "RX9D", "OERR", "FERR", "ADDEN", "CREN", "SREN", "RX9", "SPEN" });
	}

	private Program program;
	private Listing listing;
	private EquateTable equateTable;
	private ReferenceManager refMgr;

	private Register stkptr0Reg;

	private Register bsrReg;
	private Register stkptrReg;

	private RegisterContextBuilder bsrContext;

	private AddressSet disassemblyPoints;

	public Pic18Analyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.DISASSEMBLY.after().after().after());

	}

	@Override
	public boolean canAnalyze(Program p) {
		return p.getLanguage().getProcessor() == PicProcessor.PROCESSOR_PIC_18;
	}

	@Override
	public synchronized boolean added(Program p, AddressSetView set, TaskMonitor monitor,
			MessageLog log) {

		this.program = p;
		listing = program.getListing();
		refMgr = program.getReferenceManager();
		equateTable = program.getEquateTable();

		stkptr0Reg = program.getRegister(".STKPTR");

		bsrReg = program.getRegister("BSR");
		stkptrReg = program.getRegister("STKPTR");

		bsrContext = new RegisterContextBuilder(program, bsrReg, false);

		disassemblyPoints = new AddressSet();

		try {

			DirectedGraph graph = buildGraph(program, set, monitor);

			HashSet<Vertex> completed = new HashSet<Vertex>();

			LinkedList<Vertex> vertexList = new LinkedList<Vertex>();
			Vector<Vertex> entryPts = graph.getEntryPoints();
			for (Vertex v : entryPts) {
				v = getOptimalSource(graph, v);
				vertexList.add(v);
				completed.add(v);
			}

			while (!vertexList.isEmpty()) {
				Vertex v = vertexList.removeFirst();

				blockAdded((CodeBlock) v.referent(), monitor);

				Set<Vertex> children = graph.getChildren(v);
				for (Vertex child : children) {
					if (!completed.contains(child)) {
						vertexList.add(child);
						completed.add(child);
					}
				}
			}

			if (!disassemblyPoints.isEmpty()) {
				AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
				mgr.disassemble(disassemblyPoints);
			}

			return true;

		}
		catch (CancelledException e) {
			return false;
		}
		finally {
			program = null;
			listing = null;
			refMgr = null;
			equateTable = null;
			bsrReg = null;
			stkptrReg = null;
			stkptr0Reg = null;
		}
	}

	private Vertex getOptimalSource(DirectedGraph graph, Vertex v) {
		Vertex optimalVertex = v;
		while (true) {
			boolean hasFallFromVertex = false;
			for (Edge edge : graph.getIncomingEdges(optimalVertex)) {
				if (isFallThroughEdge(edge)) {
					hasFallFromVertex = true;
					optimalVertex = edge.from();
					break;
				}
			}
			if (!hasFallFromVertex) {
				return optimalVertex;
			}
		}
	}

	private boolean isFallThroughEdge(Edge edge) {
		CodeBlock fromBlock = (CodeBlock) edge.from().referent();
		CodeBlock toBlock = (CodeBlock) edge.to().referent();
		return fromBlock.getMaxAddress().add(1).equals(toBlock.getMinAddress());
	}

	private void blockAdded(CodeBlock block, TaskMonitor monitor) throws CancelledException {

		boolean newBlock = true;

		InstructionIterator instIter = listing.getInstructions(block, true);
		while (!monitor.isCancelled() && instIter.hasNext()) {
			Instruction instr = instIter.next();

			if (newBlock) {
				startNewBlock(instr);
				newBlock = false;
			}

			checkRegisterAccess(instr);

			String mnemonic = instr.getMnemonicString();
			if ("MOVFF".equals(mnemonic)) {
				markupFRegInstruction(instr, 0, RefType.READ);
				markupFRegInstruction(instr, 1, RefType.WRITE);
			}
			else if ("MOVSF".equals(mnemonic)) {
				markupFRegInstruction(instr, 1, RefType.WRITE);
			}
			else if (FREG_INSTRUCTIONS.contains(mnemonic)) {
				markupFRegInstruction(instr, 0, null);
			}
			else if (FREG_BIT_INSTRUCTIONS.contains(mnemonic)) {
				markupFRegAndBitInstruction(instr);
			}

			if (SKIP_INSTRUCTIONS.contains(mnemonic)) {
				addSkipReference(instr);
			}

		}
		bsrContext.writeValue(block.getMaxAddress());
		monitor.checkCanceled();
	}

	private Vertex getConnectedVertex(DirectedGraph graph, CodeBlock block, Vertex srcVertex) {
		boolean srcFound = false;
		Vertex[] vertices = graph.getVerticesHavingReferent(block);
		Vertex v;
		if (vertices.length != 0) {
			v = vertices[0];
			if (srcVertex != null) {
				for (Edge edge : graph.getIncomingEdges(v)) {
					srcFound = edge.from() == srcVertex;
					break;
				}
			}
		}
		else {
			v = new Vertex(block);
			graph.add(v);
		}
		if (srcVertex != null && !srcFound) {
			Edge e = new Edge(srcVertex, v);
			graph.add(e);
		}
		return v;
	}

	private DirectedGraph buildGraph(Program p, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {

		HashSet<Address> blockEntrySet = new HashSet<Address>();
		SimpleBlockModel model = new SimpleBlockModel(program);
		CodeBlockIterator blockIter = model.getCodeBlocksContaining(set, monitor);
		while (blockIter.hasNext()) {
			blockEntrySet.add(blockIter.next().getFirstStartAddress());
		}

		DirectedGraph graph = new DirectedGraph();

		Iterator<Address> iter = blockEntrySet.iterator();
		while (iter.hasNext()) {
			CodeBlock srcBlock = model.getCodeBlockAt(iter.next(), monitor);
			Vertex srcVertex = getConnectedVertex(graph, srcBlock, null);

			CodeBlockReferenceIterator refIter = srcBlock.getDestinations(monitor);
			while (refIter.hasNext()) {
				CodeBlockReference blockRef = refIter.next();
				Address destAddr = blockRef.getReference();
				if (!blockEntrySet.contains(destAddr) ||
					destAddr.equals(srcBlock.getFirstStartAddress())) {
					// skip destinations not contained within the initial set or is a self-reference
					continue;
				}
				CodeBlock destBlock = blockRef.getDestinationBlock();
				getConnectedVertex(graph, destBlock, srcVertex);
			}
		}
		return graph;
	}

	private void addSkipReference(Instruction instr) {
		try {
			Instruction nextInstr = instr.getNext();
			if (nextInstr == null) {
				return;
			}

			Address skipAddr = nextInstr.getMaxAddress().add(1);
			instr.addMnemonicReference(skipAddr, RefType.CONDITIONAL_JUMP, SourceType.ANALYSIS);

			disassemblyPoints.addRange(skipAddr, skipAddr);

			if (nextInstr.getLength() != 2) { // skip flow always skips by 2 bytes
				// Remove disassembler error bookmark caused by offcut skip which is OK
				BookmarkManager bookmarkMgr = program.getBookmarkManager();
				Address nextAddr = nextInstr.getMinAddress();
				Bookmark bookmark = bookmarkMgr.getBookmark(nextAddr.add(2), BookmarkType.ERROR,
					Disassembler.ERROR_BOOKMARK_CATEGORY);
				if (bookmark != null) {
					bookmarkMgr.removeBookmark(bookmark);
					bookmarkMgr.setBookmark(nextAddr, BookmarkType.ANALYSIS, "Offcut Skip Detected",
						"");
				}
			}
		}
		catch (AddressOutOfBoundsException e) {
			// ignore
		}

	}

	private void markupFRegAndBitInstruction(Instruction instr) {
		if (instr.getNumOperands() != 3) {
			return;
		}

		String regName = markupFRegInstruction(instr, 0, null);
		if (regName == null) {
			return;
		}

		Object[] objs = instr.getOpObjects(1);
		if (objs.length != 1 || !(objs[0] instanceof Scalar)) {
			return;
		}
		int bit = (int) ((Scalar) objs[0]).getUnsignedValue();

		// Create Equate for supported register bit values
		String[] bitNames = FREG_BIT_NAMES_MAP.get(regName);
		if (bitNames == null || bit >= bitNames.length || bitNames[bit] == null) {
			return;
		}

		String bitName = bitNames[bit];
		Equate bitEquate = equateTable.getEquate(bitName);
		if (bitEquate == null) {
			try {
				bitEquate = equateTable.createEquate(bitName, bit);
			}
			catch (Exception e) {
				return;
			}
		}

		bitEquate.addReference(instr.getMinAddress(), 1);

	}

	/**
	 * Attempt to markup FReg access instruction with register reference.
	 * 
	 * @param instr
	 * @return register name if identified, else null
	 */
	private String markupFRegInstruction(Instruction instr, int opIndex, RefType refType) {
		Object[] objs = instr.getOpObjects(opIndex);
		if (objs.length != 1) {
			return null;
		}

		Address addr;
		Register reg = null;
		if (objs[0] instanceof Register) {
			reg = ((Register) objs[0]);
			addr = reg.getAddress();
		}
		else if (objs[0] instanceof Address) {
			addr = (Address) objs[0];
			reg = program.getRegister(addr, 1);
		}
		else if (objs[0] instanceof Scalar) {

//			long offset = ((Scalar)objs[0]).getUnsignedValue();
//			Object[] accessObjs = instr.getOpObjects(instr.getNumOperands()-1);
//			if (objs.length == 1 && "BANKED".equals(accessObjs[0])) {
//				// BANKED mode
//				if (bsrSetAddr == null || !(objs[0] instanceof Scalar)) {
//					return null;
//				}
//				offset += ((long)(bsrVal & 0x0f) << 8);
//			}
//			else {
//				// ACCESS mode
//				offset = ((Scalar)objs[0]).getUnsignedValue();
//			}

			if (!bsrContext.hasValue() || !(objs[0] instanceof Scalar)) {
				return null;
			}
			long offset =
				((bsrContext.longValue() & 0x0f) << 8) + ((Scalar) objs[0]).getUnsignedValue();
			addr = program.getAddressFactory().getAddressSpace("DATA").getAddress(offset);
			reg = program.getRegister(addr);
		}
		else {
			return null;
		}

		// Determine RefType
		String mnemonic = instr.getMnemonicString();
		if (refType == null) {
			refType = RefType.READ;
			if ("CLRF".equals(mnemonic) || "MOVWF".equals(mnemonic) || "LFSR".equals(mnemonic)) {
				refType = RefType.WRITE;
			}
			else if (FREG_BIT_INSTRUCTIONS.contains(mnemonic)) {
				if ("BCF".equals(mnemonic) || "BSF".equals(mnemonic)) {
					refType = RefType.READ_WRITE;
				}
			}
			else if (opIndex == 0 && instr.getNumOperands() == 3) {
				// Detect read/write update of register
				List<?> repObjs = instr.getDefaultOperandRepresentationList(1);
				if (repObjs.size() == 1 && DEST_FREG.equals(repObjs.get(0))) {
					refType = RefType.READ_WRITE;
				}
			}
		}

		if (stkptrReg.equals(reg)) {
			addr = stkptr0Reg.getAddress();
		}

		if (addr.isMemoryAddress()) {
			refMgr.addMemoryReference(instr.getMinAddress(), addr, refType, SourceType.ANALYSIS,
				opIndex);
		}

		return reg != null ? reg.getName() : null;
	}

	private boolean isCodeAddress(Address addr) {
		return CODE_SPACE_NAME.equals(addr.getAddressSpace().getName());
	}

	private boolean startNewBlock(Instruction instr) {

		Address addr = instr.getMinAddress();

		if (addr.getOffset() == RESET_VECTOR_OFFSET ||
			addr.getOffset() == HIGH_INTERRUPT_VECTOR_OFFSET ||
			addr.getOffset() == LOW_INTERRUPT_VECTOR_OFFSET) {
			// Power-on reset or interrupt
			// If this is a wrong assumption for interrupts, the interrupt handler
			// should save and set BSR properly
			bsrContext.setValueAt(instr, 0, true);
			return true;
		}

		if (bsrContext.setValueAt(instr, addr, true)) {
			return true;
		}

		// Check for fall-through
		Address fallFromAddr = instr.getFallFrom();
		if (fallFromAddr != null) {
			if (bsrContext.setValueAt(instr, fallFromAddr, true)) {
				return true;
			}
		}

		// Find initial BSR for start of block
		ReferenceIterator refIter = refMgr.getReferencesTo(addr);
		while (refIter.hasNext()) {
			Reference ref = refIter.next();
			Address fromAddr = ref.getFromAddress();
			if (isCodeAddress(fromAddr)) {
				if (bsrContext.setValueAt(instr, fromAddr, true)) {
					return true;
				}
			}
		}
		return false;
	}

	private void checkRegisterAccess(Instruction instr) {

		if (instr.getNumOperands() == 0) {
			return;
		}
		else if ("MOVLB".equals(instr.getMnemonicString())) {
			handleBSRModification(instr);
		}
		else {
			Object[] objs = instr.getOpObjects(0);
			if (objs.length == 0) {
				return;
			}
			if (bsrReg.equals(objs[0]) || bsrReg.getAddress().equals(objs[0])) {
				handleBSRModification(instr);
			}
		}
	}

	private void handleBSRModification(Instruction instr) {
		bsrContext.writeValue(instr.getMaxAddress());
		String mnemonic = instr.getMnemonicString();
		if ("CLRF".equals(mnemonic)) {
			bsrContext.setValueAt(instr, 0, false);
		}
		else if ("BSF".equals(mnemonic)) {
			if (!bsrContext.setBitAt(instr, instr.getScalar(1), 0)) {
				// Unhandled bsr modification
				Msg.warn(this, "Unhandled BSR bit-set at: " + instr.getMinAddress());
			}
		}
		else if ("BCF".equals(mnemonic)) {
			if (!bsrContext.clearBitAt(instr, instr.getScalar(1), 0)) {
				// Unhandled bsr modification
				Msg.warn(this, "Unhandled BSR bit-set at: " + instr.getMinAddress());
			}
		}
		else if ("BTG".equals(mnemonic)) {
			Scalar s = instr.getScalar(1);
			if (s != null && bsrContext.hasValue()) {
				byte bitmask = (byte) (1 << s.getUnsignedValue());
				long bsrVal = bsrContext.longValue();
				if ((bsrVal & bitmask) == 0) {
					bsrVal = (byte) (bsrVal | bitmask); // set bit
				}
				else {
					bsrVal = (byte) (bsrVal & ~bitmask); // clear bit
				}
				bsrContext.setValueAt(instr, bsrVal, false);
			}
			else {
				// Unhandled bsr modification
				Msg.warn(this, "Unhandled BSR bit-clear at: " + instr.getMinAddress());
				bsrContext.setValueUnknown();
			}
		}
		else if ("MOVLB".equals(mnemonic)) {
			Scalar s = instr.getScalar(1);
			if (s != null) {
				bsrContext.setValueAt(instr, s.getUnsignedValue(), false);
			}
			else {
				// Unhandled bsr modification
				Msg.warn(this, "Unhandled BSR bit-clear at: " + instr.getMinAddress());
				bsrContext.setValueUnknown();
			}
		}
		else if (REG_MODIFICATION_MNEMONICS.contains(mnemonic)) {
			if (instr.getNumOperands() == 3) {
				List<?> repObjs = instr.getDefaultOperandRepresentationList(1);
				if (repObjs.size() == 1 && DEST_FREG.equals(repObjs.get(0))) {
					// Unhandled status modification
					bsrContext.setValueUnknown();
					Msg.warn(this, "Unhandled BSR change at: " + instr.getMinAddress());
				}
			}
			else if (instr.getNumOperands() == 2) {
				// Unhandled status modification
				bsrContext.setValueUnknown();
				Msg.warn(this, "Unhandled BSR change at: " + instr.getMinAddress());
			}
		}

	}
}
