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
import ghidra.program.model.address.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class Pic12Analyzer extends AbstractAnalyzer {
	private static final String NAME = "PIC-12C5xx or PIC-16C5x";
	private static final String DESCRIPTION =
		"Analyzes PIC 12-bit instructions (PIC-12C5xx or PIC-16C5x).";

	private static final int INSTRUCTION_LENGTH = 2;
	private static final long RESET_VECTOR_OFFSET = 0;

	private static final Character DEST_W = 'w';
	private static final Character DEST_FREG = 'f';

	private static final String CODE_SPACE_NAME = "CODE";

	private static final HashSet<String> WREG_MODIFICATION_MNEMONICS = new HashSet<String>();
	static {
		WREG_MODIFICATION_MNEMONICS.add("ANDLW");
		WREG_MODIFICATION_MNEMONICS.add("IORLW");
		WREG_MODIFICATION_MNEMONICS.add("XORLW");
	}

	private static final HashSet<String> REG_MODIFICATION_MNEMONICS = new HashSet<String>();
	static {
		REG_MODIFICATION_MNEMONICS.add("ADDWF");
		REG_MODIFICATION_MNEMONICS.add("ANDWF");
		REG_MODIFICATION_MNEMONICS.add("COMF");
		REG_MODIFICATION_MNEMONICS.add("DECF");
		REG_MODIFICATION_MNEMONICS.add("DECFSZ");
		REG_MODIFICATION_MNEMONICS.add("INCF");
		REG_MODIFICATION_MNEMONICS.add("INCFSZ");
		REG_MODIFICATION_MNEMONICS.add("IORWF");
		REG_MODIFICATION_MNEMONICS.add("MOVWF");
		REG_MODIFICATION_MNEMONICS.add("RLF");
		REG_MODIFICATION_MNEMONICS.add("RRF");
		REG_MODIFICATION_MNEMONICS.add("SUBWF");
		REG_MODIFICATION_MNEMONICS.add("SWAPF");
		REG_MODIFICATION_MNEMONICS.add("XORWF");
	}

	private static final HashSet<String> FREG_INSTRUCTIONS = new HashSet<String>();
	static {
		FREG_INSTRUCTIONS.add("ADDWF");
		FREG_INSTRUCTIONS.add("ANDWF");
		FREG_INSTRUCTIONS.add("CLRF");
		FREG_INSTRUCTIONS.add("COMF");
		FREG_INSTRUCTIONS.add("DECF");
		FREG_INSTRUCTIONS.add("DECFSZ");
		FREG_INSTRUCTIONS.add("INCF");
		FREG_INSTRUCTIONS.add("INCFSZ");
		FREG_INSTRUCTIONS.add("IORWF");
		FREG_INSTRUCTIONS.add("MOVF");
		FREG_INSTRUCTIONS.add("MOVWF");
		FREG_INSTRUCTIONS.add("RLF");
		FREG_INSTRUCTIONS.add("RRF");
		FREG_INSTRUCTIONS.add("SUBWF");
		FREG_INSTRUCTIONS.add("SWAPF");
		FREG_INSTRUCTIONS.add("XORWF");
	}

	private static final HashSet<String> FREG_BIT_INSTRUCTIONS = new HashSet<String>();
	static {
		FREG_BIT_INSTRUCTIONS.add("BCF");
		FREG_BIT_INSTRUCTIONS.add("BSF");
		FREG_BIT_INSTRUCTIONS.add("BTFSC");
		FREG_BIT_INSTRUCTIONS.add("BTFSS");
	}

	private static final HashSet<String> SKIP_INSTRUCTIONS = new HashSet<String>();
	static {
		SKIP_INSTRUCTIONS.add("DECFSZ");
		SKIP_INSTRUCTIONS.add("INCFSZ");
		SKIP_INSTRUCTIONS.add("BTFSC");
		SKIP_INSTRUCTIONS.add("BTFSS");
	}

	private static final HashSet<String> CALL_BRANCH_INSTRUCTIONS = new HashSet<String>();
	static {
		CALL_BRANCH_INSTRUCTIONS.add("CALL");
		CALL_BRANCH_INSTRUCTIONS.add("GOTO");
	}

	// RegName -> String[] { bit names }
	private static final HashMap<String, String[]> FREG_BIT_NAMES_MAP =
		new HashMap<String, String[]>();
	static {
		FREG_BIT_NAMES_MAP.put("STATUS",
			new String[] { "C", "DC", "Z", "!PD", "!TO", "PA0", "PA1", "GPWUF" });
		FREG_BIT_NAMES_MAP.put("GPIO",
			new String[] { "GP0", "GP1", "GP2", "GP3", "GP4", "GP5", "SDA", "SCL" });
	}

	private Program program;
	private Listing listing;
	private EquateTable equateTable;
	private ReferenceManager refMgr;

	private Register status0Reg;
	private Register fsr0Reg;
	private Register pcl0Reg;

	private Register statusReg;
	private Register fsrReg;
	private Register pclReg;
	private Register wReg;

	private Register paStatusReg;

	private RegisterContextBuilder wContext;
	private RegisterContextBuilder paContext;
	private RegisterContextBuilder fsrContext;

	private AddressSet disassemblyPoints;

	public Pic12Analyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.DISASSEMBLY.after().after().after());
	}

	@Override
	public boolean canAnalyze(Program p) {
		LanguageID languageID = p.getLanguageID();
		return languageID.equals(new LanguageID("PIC-12:LE:16:PIC-12C5xx")) ||
			languageID.equals(new LanguageID("PIC-16:LE:16:PIC-16C5x"));
	}

	@Override
	public synchronized boolean added(Program p, AddressSetView set, TaskMonitor monitor,
			MessageLog log) {

		this.program = p;
		listing = program.getListing();
		refMgr = program.getReferenceManager();
		equateTable = program.getEquateTable();

		status0Reg = program.getRegister("STATUS.0");
		fsr0Reg = program.getRegister("FSR.0");
		pcl0Reg = program.getRegister("PCL.0");

		statusReg = program.getRegister("STATUS");
		fsrReg = program.getRegister("FSR");
		pclReg = program.getRegister("PCL");
		wReg = program.getRegister("W");

		paStatusReg = program.getRegister("PA");

		wContext = new RegisterContextBuilder(program, wReg, false);
		fsrContext = new RegisterContextBuilder(program, fsrReg, false);
		paContext = new RegisterContextBuilder(program, paStatusReg, 0x3);

		disassemblyPoints = new AddressSet();

		boolean newBlock = true;
		try {
			Instruction fallThroughInstr = null;
			InstructionIterator instIter = listing.getInstructions(set, true);
			while (!monitor.isCancelled() && instIter.hasNext()) {
				Instruction instr = instIter.next();

				if (fallThroughInstr != null && instr != fallThroughInstr) {
					Address endAddr = fallThroughInstr.getMinAddress().subtract(1);
					fsrContext.writeValue(endAddr);
					paContext.writeValue(endAddr);
					newBlock = true;
				}

				if (newBlock) {
					startNewBlock(instr);
					newBlock = false;
				}

				FlowType flowType = instr.getFlowType();
				if (flowType.isCall() || flowType.isJump()) {
					handleCallOrBranch(instr);
				}

				if (!handleWRegModification(instr)) {
					checkRegisterAccess(instr);
				}

				String mnemonic = instr.getMnemonicString();
				if (FREG_INSTRUCTIONS.contains(mnemonic)) {
					markupFRegInstruction(instr);
				}
				else if (FREG_BIT_INSTRUCTIONS.contains(mnemonic)) {
					markupFRegAndBitInstruction(instr);
				}

				fallThroughInstr = getFallthrough(instr);
				if (flowType == RefType.UNCONDITIONAL_JUMP || flowType.isTerminal() ||
					fallThroughInstr == null || !set.contains(fallThroughInstr.getMinAddress())) {
					Address endAddr = instr.getMaxAddress();
					fsrContext.writeValue(endAddr);
					paContext.writeValue(endAddr);
					newBlock = true;
				}
			}

			if (!disassemblyPoints.isEmpty()) {
				AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
				mgr.disassemble(disassemblyPoints);
			}

			return true;
		}
		finally {
			program = null;
			listing = null;
			refMgr = null;
			equateTable = null;
			status0Reg = null;
			fsr0Reg = null;
			pcl0Reg = null;
			statusReg = null;
			fsrReg = null;
			pclReg = null;
			wReg = null;
			paStatusReg = null;
		}
	}

	private void markupFRegAndBitInstruction(Instruction instr) {
		if (instr.getNumOperands() != 2) {
			return;
		}

		String regName = markupFRegInstruction(instr);
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
	private String markupFRegInstruction(Instruction instr) {
		Object[] objs = instr.getOpObjects(0);
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
			long offset = ((Scalar) objs[0]).getUnsignedValue();
			if ((offset & 0x1f) >= 0x10) {
				if (!fsrContext.hasValue()) {
					return null;
				}
				offset = (fsrContext.longValue() & 0x60) + offset;
			}
			addr = program.getAddressFactory().getAddressSpace("DATA").getAddress(offset);
			reg = program.getRegister(addr);
		}
		else {
			return null;
		}

		// Determine RefType
		String mnemonic = instr.getMnemonicString();
		RefType refType = RefType.READ;
		if ("CLRF".equals(mnemonic) || "MOVWF".equals(mnemonic)) {
			refType = RefType.WRITE;
		}
		else if (FREG_BIT_INSTRUCTIONS.contains(mnemonic)) {
			if ("BCF".equals(mnemonic) || "BSF".equals(mnemonic)) {
				refType = RefType.READ_WRITE;
			}
		}
		else if (instr.getNumOperands() == 2) {
			List<?> repObjs = instr.getDefaultOperandRepresentationList(1);
			if (repObjs.size() == 1 && DEST_FREG.equals(repObjs.get(0))) {
				refType = RefType.READ_WRITE;
			}
		}

		if (statusReg.equals(reg)) {
			addr = status0Reg.getAddress();
		}
		else if (fsrReg.equals(reg)) {
			addr = fsr0Reg.getAddress();
		}
		else if (pclReg.equals(reg)) {
			addr = pcl0Reg.getAddress();
		}

		if (addr.isMemoryAddress()) {
			refMgr.addMemoryReference(instr.getMinAddress(), addr, refType, SourceType.DEFAULT, 0);
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
			fsrContext.setValueAt(instr, 0x60, true);
			paContext.setValueAt(instr, 0, true);
			wContext.setValueUnknown();
			return;
		}

		fsrContext.setValueAt(instr, instrAddr, true);
		paContext.setValueAt(instr, instrAddr, true);
		wContext.setValueAt(instr, instrAddr, true);

		Instruction fallFromInstr = getFallFrom(instr);
		if (fallFromInstr != null) {
			// Carry unknown values down if possible
			Address fallFrom = fallFromInstr.getMinAddress();
			fsrContext.setValueAt(instr, fallFrom, false);
			paContext.setValueAt(instr, fallFrom, false);
			wContext.setValueAt(instr, fallFrom, false);
		}

		else {

			// If a test w/ conditional skip was used to get here, carry down the context values
			if (instrOffset >= 4) {
				Address skipFromAddr = instrAddr.subtract(2 * INSTRUCTION_LENGTH);
				Reference ref = refMgr.getReference(skipFromAddr, instrAddr, Reference.MNEMONIC);
				if (ref != null && ref.getReferenceType() == RefType.CONDITIONAL_JUMP) {
					paContext.setValueAt(instr, skipFromAddr, false);
					fsrContext.setValueAt(instr, skipFromAddr, false);
					wContext.setValueAt(instr, skipFromAddr, false);
				}
			}

			// Assume we got here with CALL or GOTO using PCLATH, fall-through and skip case handled above
			if (!paContext.hasValue()) {
				paContext.setValueAt(instr, (instrOffset / INSTRUCTION_LENGTH) >> 9, true);
			}
		}

		// Find initial W and FSR for start of block
		ReferenceIterator refIter = refMgr.getReferencesTo(instrAddr);
		while ((!fsrContext.hasValue() || !wContext.hasValue()) && refIter.hasNext()) {
			Reference ref = refIter.next();
			Address fromAddr = ref.getFromAddress();
			if (isCodeAddress(fromAddr)) {
				fsrContext.setValueAt(instr, fromAddr, false);
				wContext.setValueAt(instr, fromAddr, false);
			}
		}

		if (!fsrContext.hasValue()) {
			Msg.warn(this, "Initial FSR unknown at: " + instrAddr);
		}

	}

	private void handleCallOrBranch(Instruction instr) {

		String mnemonic = instr.getMnemonicString();
		if (CALL_BRANCH_INSTRUCTIONS.contains(mnemonic)) {
			if (paContext.hasValue()) {
				Object[] objs = instr.getOpObjects(0);
				if (objs.length == 1 && objs[0] instanceof Scalar) {
					Scalar s = (Scalar) objs[0];
					long offset =
						((paContext.longValue() << 9) + s.getUnsignedValue()) * INSTRUCTION_LENGTH;
					Address destAddr = instr.getMinAddress().getNewAddress(offset);
					RefType flowType = instr.getFlowType().isCall() ? RefType.UNCONDITIONAL_CALL
							: RefType.UNCONDITIONAL_JUMP;
					refMgr.addMemoryReference(instr.getMinAddress(), destAddr, flowType,
						SourceType.DEFAULT, 0);
					disassembleAt(destAddr);
				}
			}
		}

		// Handle DECFSZ, INCFSZ, BTFSC and BTFSS
		else if (SKIP_INSTRUCTIONS.contains(mnemonic)) {
			Address skipAddr = instr.getMinAddress().add(2 * INSTRUCTION_LENGTH);
			refMgr.addMemoryReference(instr.getMinAddress(), skipAddr, RefType.CONDITIONAL_JUMP,
				SourceType.DEFAULT, Reference.MNEMONIC);
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
		else if ("MOVF".equals(mnemonic)) {
			modUnknown = true;
		}
		else if ("MOVLW".equals(mnemonic)) {
			Scalar s = instr.getScalar(0);
			if (s != null) {
				wContext.setValueAt(instr, s.getUnsignedValue(), false);
				return true;
			}
			modUnknown = true;
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

		Object[] objs = instr.getOpObjects(0);
		if (objs.length == 0) {
			return;
		}

		if (statusReg.equals(objs[0]) || statusReg.getAddress().equals(objs[0])) {
			handleStatusModification(instr);
		}
		else if (fsrReg.equals(objs[0]) || fsrReg.getAddress().equals(objs[0])) {
			handleFSRModification(instr);
		}
//		else if (isRead(instr, pclReg)){
//			paContext.writeValue(instr.getMaxAddress());
//			paContext.setValueAt(instr, instr.getMaxAddress().add(1).getOffset() >> 9, false);
//		}
	}

	private void handleStatusModification(Instruction instr) {
		paContext.writeValue(instr.getMaxAddress());
		String mnemonic = instr.getMnemonicString();
		if ("CLRF".equals(mnemonic)) {
			paContext.setValueAt(instr, 0, false);
		}
		else if ("BSF".equals(mnemonic)) {
			Scalar s = instr.getScalar(1);
			boolean success = false;
			if (s != null) {
				int bit = (int) s.getUnsignedValue();
				if (bit == 5 || bit == 6) {
					success = paContext.setBitAt(instr, bit - 5);
				}
				else {
					success = true; // ignore untracked portions of status reg
				}
			}
			if (!success) {
				Msg.warn(this, "Unhandled STATUS bit-set at: " + instr.getMinAddress());
			}
		}
		else if ("BCF".equals(mnemonic)) {
			Scalar s = instr.getScalar(1);
			boolean success = false;
			if (s != null) {
				int bit = (int) s.getUnsignedValue();
				if (bit == 5 || bit == 6) {
					success = paContext.clearBitAt(instr, bit - 5);
				}
				else {
					success = true; // ignore untracked portions of status reg
				}
			}
			if (!success) {
				Msg.warn(this, "Unhandled STATUS bit-set at: " + instr.getMinAddress());
			}
		}
		else if ("MOVWF".equals(mnemonic)) {
			if (wContext.hasValue()) {
				paContext.setValueAt(instr, wContext.longValue() >> 5, false);
			}
			else {
				paContext.setValueUnknown();
				Msg.warn(this, "Unhandled STATUS change at: " + instr.getMinAddress());
			}
		}
		else if (REG_MODIFICATION_MNEMONICS.contains(mnemonic)) {
			if (instr.getNumOperands() == 2) {
				List<?> repObjs = instr.getDefaultOperandRepresentationList(1);
				if (repObjs.size() == 1 && DEST_FREG.equals(repObjs.get(0))) {
					// Unhandled status modification
					paContext.setValueUnknown();
					Msg.warn(this, "Unhandled STATUS change at: " + instr.getMinAddress());
				}
			}
			else if (instr.getNumOperands() == 1) {
				// Unhandled status modification
				paContext.setValueUnknown();
				Msg.warn(this, "Unhandled STATUS change at: " + instr.getMinAddress());
			}
		}
	}

	private void handleFSRModification(Instruction instr) {
		fsrContext.writeValue(instr.getMaxAddress());
		String mnemonic = instr.getMnemonicString();
		if ("CLRF".equals(mnemonic)) {
			fsrContext.setValueAt(instr, 0, false);
		}
		else if ("BSF".equals(mnemonic)) {
			if (!fsrContext.setBitAt(instr, instr.getScalar(1), 0)) {
				fsrContext.setValueUnknown();
				Msg.warn(this, "Unhandled FSR bit-set at: " + instr.getMinAddress());
			}
		}
		else if ("BCF".equals(mnemonic)) {
			if (!fsrContext.clearBitAt(instr, instr.getScalar(1), 0)) {
				fsrContext.setValueUnknown();
				Msg.warn(this, "Unhandled FSR bit-set at: " + instr.getMinAddress());
			}
		}
		else if ("INCF".equals(mnemonic)) {
			if (fsrContext.hasValue()) {
				fsrContext.setValueAt(instr, fsrContext.longValue() + 1, false);
			}
			else {
				fsrContext.setValueUnknown();
				Msg.warn(this, "Unhandled FSR change at: " + instr.getMinAddress());
			}
		}
		else if ("DECF".equals(mnemonic)) {
			if (fsrContext.hasValue()) {
				fsrContext.setValueAt(instr, fsrContext.longValue() - 1, false);
			}
			else {
				fsrContext.setValueUnknown();
				Msg.warn(this, "Unhandled FSR change at: " + instr.getMinAddress());
			}
		}
		else if ("MOVWF".equals(mnemonic)) {
			if (wContext.hasValue()) {
				fsrContext.setValueAt(instr, wContext.longValue(), false);
			}
			else {
				fsrContext.setValueUnknown();
				Msg.warn(this, "Unhandled FSR change at: " + instr.getMinAddress());
			}
		}
		else if (REG_MODIFICATION_MNEMONICS.contains(mnemonic)) {
			if (instr.getNumOperands() == 2) {
				List<?> repObjs = instr.getDefaultOperandRepresentationList(1);
				if (repObjs.size() == 1 && DEST_FREG.equals(repObjs.get(0))) {
					if ("INCF".equals(mnemonic)) {
						// do nothing - assume this will not affect high-order FSR<6:5> bits
					}
					else {
						// Unhandled FSR modification
						fsrContext.setValueUnknown();
						Msg.warn(this, "Unhandled FSR change at: " + instr.getMinAddress());
					}
				}
			}
			else if (instr.getNumOperands() == 1) {
				// Unhandled FSR modification
				fsrContext.setValueUnknown();
				Msg.warn(this, "Unhandled FSR change at: " + instr.getMinAddress());
			}
		}
	}

	private Instruction getFallthrough(Instruction instr) {
		if (instr != null) {
			Instruction nextInstr = instr.getNext();
			if (nextInstr != null && nextInstr.getMinAddress().equals(instr.getFallThrough())) {
				return nextInstr;
			}
		}
		return null;
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

}
