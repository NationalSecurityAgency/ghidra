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

import java.math.BigInteger;
import java.util.*;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
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

public class Pic17c7xxAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "PIC-17C7xx";
	private static final String DESCRIPTION = "Analyzes PIC-17 instructions.";

	private static final int INSTRUCTION_LENGTH = 2;
	private static final long RESET_VECTOR_OFFSET = 0;
	//private static final long INTERRUPT_VECTOR_OFFSET = 4 * INSTRUCTION_LENGTH;

	private static final Character DEST_W = 'w';
	private static final Character DEST_FREG = 'f';

	private static final Character S_0 = '0'; // Update both operand fReg and WREG
	//private static final Character S_1 = '1'; // Update only operand fReg

	//private static final String PIC17C7xx_LANG = "Sleigh-PIC-17C7xx";

	private static final String CODE_SPACE_NAME = "CODE";

	private static final HashSet<String> WREG_MODIFICATION_MNEMONICS = new HashSet<String>();
	static {
		WREG_MODIFICATION_MNEMONICS.add("ADDLW");
		WREG_MODIFICATION_MNEMONICS.add("ANDLW");
		WREG_MODIFICATION_MNEMONICS.add("IORLW");
		WREG_MODIFICATION_MNEMONICS.add("MOVLW");
		WREG_MODIFICATION_MNEMONICS.add("SUBLW");
		WREG_MODIFICATION_MNEMONICS.add("XORLW");
	}

	private static final HashSet<String> REG_S_MODIFICATION_MNEMONICS = new HashSet<String>();
	static {
		REG_S_MODIFICATION_MNEMONICS.add("CLRF");
		REG_S_MODIFICATION_MNEMONICS.add("DAW");
		REG_S_MODIFICATION_MNEMONICS.add("NEGW");
		REG_S_MODIFICATION_MNEMONICS.add("SETF");
	}

	// Do not include REG_S_MODIFICATION_MNEMONICS here
	private static final HashSet<String> REG_MODIFICATION_MNEMONICS = new HashSet<String>();
	static {
		REG_MODIFICATION_MNEMONICS.add("ADDWF");
		REG_MODIFICATION_MNEMONICS.add("ADDWFC");
		REG_MODIFICATION_MNEMONICS.add("ANDWF");
		REG_MODIFICATION_MNEMONICS.add("COMF");
		REG_MODIFICATION_MNEMONICS.add("DECF");
		REG_MODIFICATION_MNEMONICS.add("DECFSZ");
		REG_MODIFICATION_MNEMONICS.add("DCFSNZ");
		REG_MODIFICATION_MNEMONICS.add("INCF");
		REG_MODIFICATION_MNEMONICS.add("INCFSZ");
		REG_MODIFICATION_MNEMONICS.add("INCFNZ");
		REG_MODIFICATION_MNEMONICS.add("IORWF");
		REG_MODIFICATION_MNEMONICS.add("MOVWF");
		REG_MODIFICATION_MNEMONICS.add("RLCF");
		REG_MODIFICATION_MNEMONICS.add("RLNCF");
		REG_MODIFICATION_MNEMONICS.add("RRCF");
		REG_MODIFICATION_MNEMONICS.add("RRNCF");
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
		FREG_INSTRUCTIONS.add("CPFSEQ");
		FREG_INSTRUCTIONS.add("CPFSGT");
		FREG_INSTRUCTIONS.add("CPFSLT");
		FREG_INSTRUCTIONS.add("DAW");
		FREG_INSTRUCTIONS.add("DECF");
		FREG_INSTRUCTIONS.add("DECFSZ");
		FREG_INSTRUCTIONS.add("DCFSNZ");
		FREG_INSTRUCTIONS.add("INCF");
		FREG_INSTRUCTIONS.add("INCFSZ");
		FREG_INSTRUCTIONS.add("INFSNZ");
		FREG_INSTRUCTIONS.add("IORWF");
		FREG_INSTRUCTIONS.add("MOVWF");
		FREG_INSTRUCTIONS.add("MULWF");
		FREG_INSTRUCTIONS.add("NEGW");
		FREG_INSTRUCTIONS.add("RLCF");
		FREG_INSTRUCTIONS.add("RLNCF");
		FREG_INSTRUCTIONS.add("RRCF");
		FREG_INSTRUCTIONS.add("RRNCF");
		FREG_INSTRUCTIONS.add("SETF");
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
		FREG_BIT_INSTRUCTIONS.add("BTFSC");
		FREG_BIT_INSTRUCTIONS.add("BTFSS");
		FREG_BIT_INSTRUCTIONS.add("BTG");
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
		FREG_BIT_NAMES_MAP.put("ALUSTA",
			new String[] { "C", "DC", "Z", "OV", "FS0", "FS1", "FS2", "FS3" });
		FREG_BIT_NAMES_MAP.put("T0STA",
			new String[] { null, "T0SP0", "T0PS1", "T0PS2", "T0PS3", "T0CS", "T0SE", "INTEDG" });
		FREG_BIT_NAMES_MAP.put("CPUSTA",
			new String[] { "!BOR", "!POR", "!PD", "!TO", "GLINTD", "STKAV" });
		FREG_BIT_NAMES_MAP.put("INTSTA",
			new String[] { "INTE", "T0IE", "T0CKIE", "PEIE", "INTF", "T0IF", "T0CKIF", "PEIF" });
		FREG_BIT_NAMES_MAP.put("RCSTA1",
			new String[] { "RX9D", "OERR", "FERR", null, "CREN", "SREN", "RX9", "SPEN" });
		FREG_BIT_NAMES_MAP.put("TXSTA1",
			new String[] { "TX9D", "TRMT", null, null, "SYNC", "TXEN", "TX9", "CSRC" });
		FREG_BIT_NAMES_MAP.put("PIR1", new String[] { "RC1IF", "TX1IF", "CA1IF", "CA2IF", "TMR1IF",
			"TMR2IF", "TMR3IF", "RBIF" });
		FREG_BIT_NAMES_MAP.put("PIE1", new String[] { "RC1IE", "TX1IE", "CA1IE", "CA2IE", "TMR1IE",
			"TMR2IE", "TMR3IE", "RBIE" });
		FREG_BIT_NAMES_MAP.put("PW1DCL",
			new String[] { null, null, null, null, null, null, "DC0", "DC1" });
		FREG_BIT_NAMES_MAP.put("PW2DCL",
			new String[] { null, null, null, null, null, "TM2PW2", "DC0", "DC1" });
		FREG_BIT_NAMES_MAP.put("PW1DCH",
			new String[] { "DC2", "DC3", "DC4", "DC5", "DC6", "DC7", "DC8", "DC9" });
		FREG_BIT_NAMES_MAP.put("PW2DCH",
			new String[] { "DC2", "DC3", "DC4", "DC5", "DC6", "DC7", "DC8", "DC9" });
		FREG_BIT_NAMES_MAP.put("TCON1", new String[] { "TMR1CS", "TMR2CS", "TMR3CS", "T16",
			"CA1ED0", "CA1ED1", "CA2ED0", "CA2ED1" });
		FREG_BIT_NAMES_MAP.put("TCON2", new String[] { "TMR1ON", "TMR2ON", "TMR3ON", "CA1!PR3",
			"PWM1ON", "PWM2ON", "CA1OVF", "CA2OVF" });
		FREG_BIT_NAMES_MAP.put("PIR2",
			new String[] { "RC2IF", "TX2IF", "CA3IF", "CA4IF", null, "ADIF", "BCLIF", "SSPIF" });
		FREG_BIT_NAMES_MAP.put("PIE2",
			new String[] { "RC2IE", "TX2IF", "CA3IF", "CA4IF", null, "ADIE", "BCLIE", "SSPIE" });
		FREG_BIT_NAMES_MAP.put("RCSTA2",
			new String[] { "RX9D", "OERR", "FERR", null, "CREN", "SREN", "RX9", "SPEN" });
		FREG_BIT_NAMES_MAP.put("TXSTA2",
			new String[] { "TX9D", "TRMT", null, null, "SYNC", "TXEN", "TX9", "CSRC" });
		FREG_BIT_NAMES_MAP.put("ADCON0",
			new String[] { "ADON", null, "GO!DONE", null, "CHS0", "CHS1", "CHS2", "CHS3" });
		FREG_BIT_NAMES_MAP.put("ADCON1",
			new String[] { "PCFG0", "PCFG1", "PCFG2", "PCFG3", null, "ADFM", "ADCS0", "ADCS1" });

	}

	private Program program;
	private Listing listing;
	private EquateTable equateTable;
	private ReferenceManager refMgr;

	private Register alustaReg;
	private Register bsrReg;
	private Register pclathReg;
	private Register pclReg;
	private Register wReg;

	private Register fs32Reg;
	private Register fs10Reg;

	private RegisterContextBuilder wContext;
	private RegisterContextBuilder pclathContext;
	private RegisterContextBuilder fs32Context;
	private RegisterContextBuilder fs10Context;
	private RegisterContextBuilder bsrContext;

	private AddressSet disassemblyPoints;
	private AddressSet clearPoints;

	public Pic17c7xxAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.DISASSEMBLY.after().after().after());
	}

	@Override
	public boolean canAnalyze(Program p) {
		return p.getLanguage().getProcessor() == PicProcessor.PROCESSOR_PIC_17;
	}

	@Override
	public synchronized boolean added(Program p, AddressSetView set, TaskMonitor monitor,
			MessageLog log) {

		this.program = p;
		listing = program.getListing();
		refMgr = program.getReferenceManager();
		equateTable = program.getEquateTable();

		alustaReg = program.getRegister("ALUSTA");
		pclathReg = program.getRegister("PCLATH");
		pclReg = program.getRegister("PCL");
		wReg = program.getRegister("WREG");
		bsrReg = program.getRegister("BSR");

		fs32Reg = program.getRegister("FS32");
		fs10Reg = program.getRegister("FS10");

		// WREG context (not written to program)
		wContext = new RegisterContextBuilder(program, wReg, false);

		// Only PCLATH<4:3> are of interest for CALL and GOTO
		pclathContext = new RegisterContextBuilder(program, pclathReg, 0xff);

		// FS32 and FS10 are 2-bit registers representing ALUSTA<7:6> and ALUSTA<5:4>
		fs32Context = new RegisterContextBuilder(program, fs32Reg, 0x3);
		fs10Context = new RegisterContextBuilder(program, fs10Reg, 0x3);

		// BSR is an 8-bit register containing the bank select nibbles
		bsrContext = new RegisterContextBuilder(program, bsrReg, 0xff);

		disassemblyPoints = new AddressSet();
		clearPoints = new AddressSet();

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

			if (!clearPoints.isEmpty()) {
				AddressRangeIterator ranges = clearPoints.getAddressRanges();
				while (ranges.hasNext()) {
					AddressRange range = ranges.next();
					program.getListing().clearCodeUnits(range.getMinAddress(),
						range.getMaxAddress(), false);
				}
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
			alustaReg = null;
			pclathReg = null;
			pclReg = null;
			wReg = null;
			fs32Reg = null;
			fs10Reg = null;
			bsrReg = null;
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

	private void blockAdded(CodeBlock block, TaskMonitor monitor) throws CancelledException {

		boolean newBlock = true;

		InstructionIterator instIter = listing.getInstructions(block, true);
		while (!monitor.isCancelled() && instIter.hasNext()) {
			Instruction instr = instIter.next();

			if (newBlock) {
				startNewBlock(instr);
				newBlock = false;
			}

			FlowType flowType = instr.getFlowType();
			if (flowType.isCall() || flowType.isJump()) {
				handleCallOrBranch(instr);
			}

			String mnemonic = instr.getMnemonicString();
			if (FREG_INSTRUCTIONS.contains(mnemonic)) {
				markupFRegInstruction(instr, 0, null);
			}
			else if ("MOVFP".equals(mnemonic) || "MOVPF".equals(mnemonic)) {
				markupFRegInstruction(instr, 0, RefType.READ);
				markupFRegInstruction(instr, 1, RefType.WRITE);
			}
			else if (mnemonic.equals("TABLRD")) {
				markupFRegInstruction(instr, 2, RefType.WRITE);
			}
			else if (mnemonic.equals("TLRD")) {
				markupFRegInstruction(instr, 1, RefType.WRITE);
			}
			else if (mnemonic.equals("TABLWT")) {
				markupFRegInstruction(instr, 2, RefType.READ);
			}
			else if (mnemonic.equals("TLWT")) {
				markupFRegInstruction(instr, 1, RefType.READ);
			}
			else if (FREG_BIT_INSTRUCTIONS.contains(mnemonic)) {
				markupFRegAndBitInstruction(instr);
			}
			else if ("BADCALL".equals(mnemonic)) {
				// Handle BADCALL which should be cleared
				Address addr = instr.getMinAddress();
				clearPoints.addRange(addr, addr);
			}

			if (!handleWRegModification(instr)) {
				checkRegisterAccess(instr);
			}

		}
		pclathContext.writeValue(block.getMaxAddress());
		fs32Context.writeValue(block.getMaxAddress());
		fs10Context.writeValue(block.getMaxAddress());
		bsrContext.writeValue(block.getMaxAddress());
		monitor.checkCanceled();
	}

	private void markupFRegAndBitInstruction(Instruction instr) {
		if (instr.getNumOperands() != 2) {
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
			return ((Register) objs[0]).getName();
		}
		else if (objs[0] instanceof Address) {
			addr = (Address) objs[0];
			reg = program.getRegister(addr, 1);
		}
		else if (objs[0] instanceof Scalar) {
			long offset = ((Scalar) objs[0]).getUnsignedValue();
			long bank = 0;
			if (offset >= 0x10 && offset <= 0x17) {
				if (!bsrContext.hasValue()) {
					return null;
				}
				bank = bsrContext.longValue() & 0x0f;
			}
			else if (offset >= 0x20) {
				if (!bsrContext.hasValue()) {
					return null;
				}
				bank = bsrContext.longValue() >> 4;
			}
			offset += bank << 8;
			addr = program.getAddressFactory().getAddressSpace("DATA").getAddress(offset);
			reg = program.getRegister(addr);
		}
		else {
			return null;
		}

		// Determine RefType
		if (refType == null) {
			refType = RefType.READ;
			String mnemonic = instr.getMnemonicString();
			if ("CLRF".equals(mnemonic) || "MOVWF".equals(mnemonic)) {
				refType = RefType.WRITE;
			}
			else if (FREG_BIT_INSTRUCTIONS.contains(mnemonic)) {
				if ("BCF".equals(mnemonic) || "BSF".equals(mnemonic)) {
					refType = RefType.READ_WRITE;
				}
			}
			else if (opIndex == 0 && instr.getNumOperands() == 2) {
				List<?> repObjs = instr.getDefaultOperandRepresentationList(1);
				if (repObjs.size() == 1 && DEST_FREG.equals(repObjs.get(0))) {
					refType = RefType.READ_WRITE;
				}
			}
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

	private void startNewBlock(Instruction instr) {

		Address instrAddr = instr.getMinAddress();
		long instrOffset = instrAddr.getOffset();

		if (instrOffset == RESET_VECTOR_OFFSET) {
			// Power-on reset or interrupt condition
			bsrContext.setValueAt(instr, 0, true);
			fs32Context.setValueAt(instr, 0x3, true);
			fs10Context.setValueAt(instr, 0x3, true);
			pclathContext.setValueAt(instr, 0, true);
			wContext.setValueUnknown();
			return;
		}

		pclathContext.setValueAt(instr, instrAddr, true);
		bsrContext.setValueAt(instr, instrAddr, true);
		fs32Context.setValueAt(instr, instrAddr, true);
		fs10Context.setValueAt(instr, instrAddr, true);
		wContext.setValueAt(instr, instrAddr, true);

		Instruction fallFromInstr = getFallFrom(instr);
		if (fallFromInstr != null) {
			// Carry value down
			Address fallFrom = fallFromInstr.getMinAddress();
			pclathContext.setValueAt(instr, fallFrom, false);
			bsrContext.setValueAt(instr, fallFrom, false);
			fs32Context.setValueAt(instr, fallFrom, false);
			fs10Context.setValueAt(instr, fallFrom, false);
			wContext.setValueAt(instr, fallFrom, false);
		}

		else {
			// If a test w/ conditional skip was used to get here, carry down the context values
			if (instrOffset >= 4) {
				Address skipFromAddr = instrAddr.subtract(2 * INSTRUCTION_LENGTH);
				Reference ref = refMgr.getReference(skipFromAddr, instrAddr, Reference.MNEMONIC);
				if (ref != null && ref.getReferenceType() == RefType.CONDITIONAL_JUMP) {
					pclathContext.setValueAt(instr, skipFromAddr, false);
					bsrContext.setValueAt(instr, skipFromAddr, false);
					fs32Context.setValueAt(instr, skipFromAddr, false);
					fs10Context.setValueAt(instr, skipFromAddr, false);
					wContext.setValueAt(instr, skipFromAddr, false);
				}
			}

		}

		// Find initial context for start of block
		ReferenceIterator refIter = refMgr.getReferencesTo(instrAddr);
		while ((!pclathContext.hasValue() || !bsrContext.hasValue() || !fs32Context.hasValue() ||
			!fs10Context.hasValue() || !wContext.hasValue()) && refIter.hasNext()) {
			Reference ref = refIter.next();
			Address fromAddr = ref.getFromAddress();
			if (isCodeAddress(fromAddr)) {
				pclathContext.setValueAt(instr, fromAddr, false);
				bsrContext.setValueAt(instr, fromAddr, false);
				fs32Context.setValueAt(instr, fromAddr, false);
				fs10Context.setValueAt(instr, fromAddr, false);
				wContext.setValueAt(instr, fromAddr, false);
				break;
			}
		}

	}

	private void handleCallOrBranch(Instruction instr) {

		String mnemonic = instr.getMnemonicString();
		if ("GOTO".equals(mnemonic) || "CALL".equals(mnemonic)) {
			// The instructions modify PCLATH
			Address destAddr = instr.getAddress(0);
			if (destAddr != null) {
				long val = destAddr.getOffset() >> 9;
				try {
					program.getProgramContext().setValue(pclathReg, destAddr, destAddr,
						BigInteger.valueOf(val));
				}
				catch (ContextChangeException e) {
					// ignore - we should be manipulating the "context-register"
				}
			}
		}

		else if ("LCALL".equals(mnemonic)) {
			Object[] objs = instr.getOpObjects(0);
			if (objs.length == 1 && objs[0] instanceof Scalar) {
				Scalar s = (Scalar) objs[0];
				handleComputedFlow(instr, s.getUnsignedValue(), 0);
			}
		}

		// Handle DECFSZ, INCFSZ, BTFSC and BTFSS
		else if (SKIP_INSTRUCTIONS.contains(mnemonic)) {
			Address skipAddr = instr.getMinAddress().add(2 * INSTRUCTION_LENGTH);
			refMgr.addMemoryReference(instr.getMinAddress(), skipAddr, RefType.CONDITIONAL_JUMP,
				SourceType.ANALYSIS, Reference.MNEMONIC);
			disassembleAt(skipAddr);
		}

	}

	private void disassembleAt(Address addr) {
		if (listing.getInstructionAt(addr) == null) {
			disassemblyPoints.addRange(addr, addr);
		}
	}

	private boolean handleWRegModification(Instruction instr) {
		String mnemonic = instr.getMnemonicString();
		boolean modUnknown = false;
		if ("CLRW".equals(mnemonic)) {
			wContext.setValueAt(instr, 0, false);
			return true;
		}
		else if ("MOVLW".equals(mnemonic)) {
			Scalar s = instr.getScalar(0);
			if (s != null) {
				wContext.setValueAt(instr, s.getUnsignedValue(), false);
				return true;
			}
			modUnknown = true;
		}
		else if ("MOVFP".equals(mnemonic) || "MOVPF".equals(mnemonic)) {
			Object[] objs = instr.getOpObjects(1);
			if (objs.length == 0) {
				return false;
			}
			if (wReg.equals(objs[0]) || wReg.getAddress().equals(objs[0])) {
				wContext.setValueUnknown();
				return true;
			}
		}
		else if (REG_S_MODIFICATION_MNEMONICS.contains(mnemonic) && instr.getNumOperands() == 2) {
			List<?> repObjs = instr.getDefaultOperandRepresentationList(1);
			if (repObjs.size() == 1 && S_0.equals(repObjs.get(0))) {
				// Unhandled W modification
				wContext.setValueUnknown();
				return false; // allow operand-0 register modiofication to be examined
			}
		}
		else if (REG_MODIFICATION_MNEMONICS.contains(mnemonic) && instr.getNumOperands() == 2) {
			List<?> repObjs = instr.getDefaultOperandRepresentationList(1);
			if (repObjs.size() == 1 && DEST_W.equals(repObjs.get(0))) {
				// Unhandled W modification
				wContext.setValueUnknown();
				return true;
			}
		}
		else if (WREG_MODIFICATION_MNEMONICS.contains(mnemonic)) {
			modUnknown = true;
		}

		if (modUnknown) {
			wContext.setValueUnknown();
			return true;
		}

		return false;
	}

	private void checkRegisterAccess(Instruction instr) {

		if (instr.getNumOperands() == 0) {
			return;
		}

		String mnemonic = instr.getMnemonicString();

		if ("MOVLB".equals(mnemonic)) {
			bsrContext.writeValue(instr.getMaxAddress());
			Scalar s = instr.getScalar(0);
			if (s != null) {
				long value = (bsrContext.hasValue() ? bsrContext.longValue() : 0) & 0xf0;
				value |= s.getUnsignedValue() & 0xf;
				bsrContext.setValueAt(instr, value, false);
			}
			else {
				bsrContext.setValueUnknown();
			}
			return;
		}

		if ("MOVLR".equals(mnemonic)) {
			bsrContext.writeValue(instr.getMaxAddress());
			Scalar s = instr.getScalar(0);
			if (s != null) {
				long value = (bsrContext.hasValue() ? bsrContext.longValue() : 0) & 0x0f;
				value |= (s.getUnsignedValue() & 0xf) << 4;
				bsrContext.setValueAt(instr, value, false);
			}
			else {
				bsrContext.setValueUnknown();
			}
			return;
		}

		int opIndex = 0;
		if ("MOVFP".equals(mnemonic) || "MOVPF".equals(mnemonic)) {
			opIndex = 1;
		}

		Object[] objs = instr.getOpObjects(opIndex);
		if (objs.length == 0) {
			return;
		}

		if (alustaReg.equals(objs[0]) || alustaReg.getAddress().equals(objs[0])) {
			handleStatusModification(instr);
		}
		if (bsrReg.equals(objs[0]) || bsrReg.getAddress().equals(objs[0])) {
			handleBSRModification(instr);
		}
		else if (pclathReg.equals(objs[0]) || pclathReg.getAddress().equals(objs[0])) {
			handlePclathModification(instr);
		}
		else if (pclReg.equals(objs[0]) || pclReg.getAddress().equals(objs[0])) {
			handlePclModification(instr);
		}
		else if (isRead(instr, pclReg)) {
			pclathContext.writeValue(instr.getMaxAddress());
			pclathContext.setValueAt(instr, instr.getMaxAddress().add(1).getOffset() >> 8, false);
		}
	}

	private void handleStatusModification(Instruction instr) {
		fs32Context.writeValue(instr.getMaxAddress());
		fs10Context.writeValue(instr.getMaxAddress());
		String mnemonic = instr.getMnemonicString();
		if ("CLRF".equals(mnemonic)) {
			fs32Context.setValueAt(instr, 0, false);
			fs10Context.setValueAt(instr, 0, false);
		}
		else if ("SETF".equals(mnemonic)) {
			fs32Context.setValueAt(instr, 0x3, false);
			fs10Context.setValueAt(instr, 0x3, false);
		}
		else if ("BSF".equals(mnemonic)) {
			Scalar s = instr.getScalar(1);
			boolean success = false;
			if (s != null) {
				int bit = (int) s.getUnsignedValue();
				if (bit == 6 || bit == 7) {
					success = fs32Context.setBitAt(instr, bit - 6);
				}
				else if (bit == 4 || bit == 5) {
					success = fs10Context.setBitAt(instr, bit - 4);
				}
				else {
					success = true; // ignore untracked portions of alusta reg
				}
			}
			if (!success) {
				Msg.warn(this, "Unhandled ALUSTA bit-set at: " + instr.getMinAddress());
			}
		}
		else if ("BCF".equals(mnemonic)) {
			Scalar s = instr.getScalar(1);
			boolean success = false;
			if (s != null) {
				int bit = (int) s.getUnsignedValue();
				if (bit == 6 || bit == 7) {
					success = fs32Context.clearBitAt(instr, bit - 6);
				}
				else if (bit == 4 || bit == 5) {
					success = fs10Context.clearBitAt(instr, bit - 4);
				}
				else {
					success = true; // ignore untracked portions of alusta reg
				}
			}
			if (!success) {
				Msg.warn(this, "Unhandled ALUSTA bit-set at: " + instr.getMinAddress());
			}
		}
		else if ("BTG".equals(mnemonic)) {
			Scalar s = instr.getScalar(1);
			if (s != null) {
				byte bit = (byte) s.getUnsignedValue();

				RegisterContextBuilder ctx;
				if (bit == 6 || bit == 7) {
					ctx = fs32Context;
					bit -= 6;
				}
				else if (bit == 4 || bit == 5) {
					ctx = fs10Context;
					bit -= 4;
				}
				else {
					return;
				}
				if (!ctx.hasValue()) {
					return;
				}
				byte bitmask = (byte) (1 << bit);
				long fsVal = ctx.longValue();
				if ((fsVal & bitmask) == 0) {
					fsVal = (byte) (fsVal | bitmask); // set bit
				}
				else {
					fsVal = (byte) (fsVal & ~bitmask); // clear bit
				}
				ctx.setValueAt(instr, fsVal, false);
			}
			else {
				// Unhandled ALUSTA modification
				Msg.warn(this, "Unhandled ALUSTA bit-toggle at: " + instr.getMinAddress());
				fs32Context.setValueUnknown();
				fs10Context.setValueUnknown();
			}
		}
		else if ("MOVWF".equals(mnemonic)) {
			if (wContext.hasValue()) {
				fs32Context.setValueAt(instr, wContext.longValue() >> 6, false);
				fs10Context.setValueAt(instr, wContext.longValue() >> 4, false);
			}
			else {
				fs32Context.setValueUnknown();
				fs10Context.setValueUnknown();
				Msg.warn(this, "Unhandled ALUSTA change at: " + instr.getMinAddress());
			}
		}
		else if ("MOVFP".equals(mnemonic) || "MOVPF".equals(mnemonic)) {
			Object[] objs = instr.getOpObjects(0);
			if (objs.length == 0 && (wReg.equals(objs[0]) || wReg.getAddress().equals(objs[0])) &&
				wContext.hasValue()) {
				fs32Context.setValueAt(instr, wContext.longValue() >> 6, false);
				fs10Context.setValueAt(instr, wContext.longValue() >> 4, false);
			}
			else {
				fs32Context.setValueUnknown();
				fs10Context.setValueUnknown();
				Msg.warn(this, "Unhandled ALUSTA change at: " + instr.getMinAddress());
			}
		}
		else if (REG_S_MODIFICATION_MNEMONICS.contains(mnemonic)) {
			fs32Context.setValueUnknown();
			fs10Context.setValueUnknown();
			Msg.warn(this, "Unhandled ALUSTA change at: " + instr.getMinAddress());
		}
		else if (REG_MODIFICATION_MNEMONICS.contains(mnemonic)) {
			if (instr.getNumOperands() == 2) { // REG_D type instructions
				List<?> repObjs = instr.getDefaultOperandRepresentationList(1);
				if (repObjs.size() == 1 && DEST_FREG.equals(repObjs.get(0))) {
					// Unhandled alusta modification
					fs32Context.setValueUnknown();
					fs10Context.setValueUnknown();
					Msg.warn(this, "Unhandled ALUSTA change at: " + instr.getMinAddress());
				}
			}
			else if (instr.getNumOperands() == 1) {
				// Unhandled alusta modification
				fs32Context.setValueUnknown();
				fs10Context.setValueUnknown();
				Msg.warn(this, "Unhandled ALUSTA change at: " + instr.getMinAddress());
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
				Msg.warn(this, "Unhandled BSR bit-toggle at: " + instr.getMinAddress());
				bsrContext.setValueUnknown();
			}
		}
		else if ("MOVWF".equals(mnemonic)) {
			if (wContext.hasValue()) {
				bsrContext.setValueAt(instr, wContext.longValue(), false);
			}
			else {
				bsrContext.setValueUnknown();
				Msg.warn(this, "Unhandled BSR change at: " + instr.getMinAddress());
			}
		}
		else if ("MOVFP".equals(mnemonic) || "MOVPF".equals(mnemonic)) {
			Object[] objs = instr.getOpObjects(0);
			if (objs.length == 0 && (wReg.equals(objs[0]) || wReg.getAddress().equals(objs[0])) &&
				wContext.hasValue()) {
				bsrContext.setValueAt(instr, wContext.longValue(), false);
			}
			else {
				bsrContext.setValueUnknown();
				Msg.warn(this, "Unhandled BSR change at: " + instr.getMinAddress());
			}
		}
		else if (REG_S_MODIFICATION_MNEMONICS.contains(mnemonic)) {
			bsrContext.setValueUnknown();
			Msg.warn(this, "Unhandled BSR change at: " + instr.getMinAddress());
		}
		else if (REG_MODIFICATION_MNEMONICS.contains(mnemonic)) {
			if (instr.getNumOperands() == 2) { // REG_D type instructions
				List<?> repObjs = instr.getDefaultOperandRepresentationList(1);
				if (repObjs.size() == 1 && DEST_FREG.equals(repObjs.get(0))) {
					// Unhandled alusta modification
					bsrContext.setValueUnknown();
					Msg.warn(this, "Unhandled BSR change at: " + instr.getMinAddress());
				}
			}
			else if (instr.getNumOperands() == 1) {
				// Unhandled alusta modification
				bsrContext.setValueUnknown();
				Msg.warn(this, "Unhandled BSR change at: " + instr.getMinAddress());
			}
		}

	}

	private void handlePclathModification(Instruction instr) {
		pclathContext.writeValue(instr.getMaxAddress());
		String mnemonic = instr.getMnemonicString();
		if ("CLRF".equals(mnemonic)) {
			pclathContext.setValueAt(instr, 0, false);
		}
		else if ("BSF".equals(mnemonic)) {
			if (!pclathContext.setBitAt(instr, instr.getScalar(1), 0)) {
//				 Unhandled PCLATH modification
				Msg.warn(this, "Unhandled PCLATH bit-set at: " + instr.getMinAddress());
			}
		}
		else if ("BCF".equals(mnemonic)) {
			if (!pclathContext.clearBitAt(instr, instr.getScalar(1), 0)) {
//				 Unhandled PCLATH modification
				Msg.warn(this, "Unhandled PCLATH bit-set at: " + instr.getMinAddress());
			}
		}
		else if ("INCF".equals(mnemonic)) {
			if (pclathContext.hasValue()) {
				pclathContext.setValueAt(instr, pclathContext.longValue() + 1, false);
			}
			else {
				pclathContext.setValueUnknown();
				Msg.warn(this, "Unhandled PCLATH change at: " + instr.getMinAddress());
			}
		}
		else if ("DECF".equals(mnemonic)) {
			if (pclathContext.hasValue()) {
				pclathContext.setValueAt(instr, pclathContext.longValue() - 1, false);
			}
			else {
				pclathContext.setValueUnknown();
				Msg.warn(this, "Unhandled PCLATH change at: " + instr.getMinAddress());
			}
		}
		else if ("MOVWF".equals(mnemonic)) {
			if (wContext.hasValue()) {
				pclathContext.setValueAt(instr, wContext.longValue(), false);
			}
			else {
				pclathContext.setValueUnknown();
				Msg.warn(this, "Unhandled PCLATH change at: " + instr.getMinAddress());
			}
		}
		else if ("MOVFP".equals(mnemonic) || "MOVPF".equals(mnemonic)) {
			Object[] objs = instr.getOpObjects(0);
			if (objs.length == 0 && (wReg.equals(objs[0]) || wReg.getAddress().equals(objs[0])) &&
				wContext.hasValue()) {
				pclathContext.setValueAt(instr, wContext.longValue(), false);
			}
			else {
				pclathContext.setValueUnknown();
				Msg.warn(this, "Unhandled PCLATH change at: " + instr.getMinAddress());
			}
		}
		else if (REG_S_MODIFICATION_MNEMONICS.contains(mnemonic)) {
			pclathContext.setValueUnknown();
			Msg.warn(this, "Unhandled PCLATH change at: " + instr.getMinAddress());
		}
		else if (REG_MODIFICATION_MNEMONICS.contains(mnemonic)) {
			if (instr.getNumOperands() == 2) {
				List<?> repObjs = instr.getDefaultOperandRepresentationList(1);
				if (repObjs.size() == 1 && DEST_FREG.equals(repObjs.get(0))) {
					// Unhandled alusta modification
					pclathContext.setValueUnknown();
					Msg.warn(this, "Unhandled PCLATH change at: " + instr.getMinAddress());
				}
			}
			else if (instr.getNumOperands() == 1) {
				// Unhandled alusta modification
				pclathContext.setValueUnknown();
				Msg.warn(this, "Unhandled PCLATH change at: " + instr.getMinAddress());
			}
		}
	}

	private void handlePclModification(Instruction instr) {
		String mnemonic = instr.getMnemonicString();
		if ("MOVWF".equals(mnemonic)) {
			if (wContext.hasValue()) {
				handleComputedFlow(instr, wContext.longValue(), Reference.MNEMONIC);
			}
			else {
				Msg.warn(this,
					"Unhandled PCL modification (WREG unknown): " + instr.getMinAddress());
			}
		}
		else if ("MOVFP".equals(mnemonic) || "MOVPF".equals(mnemonic)) {
			Object[] objs = instr.getOpObjects(0);
			if (objs.length == 0 && (wReg.equals(objs[0]) || wReg.getAddress().equals(objs[0])) &&
				wContext.hasValue()) {
				handleComputedFlow(instr, wContext.longValue(), Reference.MNEMONIC);
			}
			else {
				Msg.warn(this,
					"Unhandled PCL modification (WREG unknown): " + instr.getMinAddress());
			}
		}
	}

	private void handleComputedFlow(Instruction instr, long pclByte, int refOpIndex) {
		if (pclathContext.hasValue()) {
			long offset = ((pclathContext.longValue() << 8) + pclByte) * 2;
			Address destAddr = instr.getMinAddress().getNewAddress(offset);
			refMgr.addMemoryReference(instr.getMinAddress(), destAddr, instr.getFlowType(),
				SourceType.ANALYSIS, refOpIndex);
			if (listing.getUndefinedDataAt(destAddr) != null) {
				try {
					program.getProgramContext().setValue(pclathReg, destAddr, destAddr,
						pclathContext.value());
					disassembleAt(destAddr);
				}
				catch (ContextChangeException e) {
					Msg.error(this, "Unexpected Error", e);
				}
			}
		}
	}

	private Instruction getFallFrom(Instruction instr) {
		if (instr != null) {
			Address fallFromAddr = instr.getFallFrom();
			if (fallFromAddr != null) {
				return listing.getInstructionAt(fallFromAddr);
			}
		}
		return null;
	}

	private boolean isRead(Instruction instr, Register reg) {
		Object[] objs = instr.getInputObjects();
		for (Object obj : objs) {
			if (obj instanceof Address && reg.getAddress().equals(obj)) {
				return true;
			}
		}
		return false;
	}

}
