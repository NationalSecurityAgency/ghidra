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

import java.util.HashSet;

import ghidra.app.services.*;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class PicSwitchAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "PIC Switch Tables";
	private static final String DESCRIPTION = "Analyzes PIC Switch instructions.";

	//private static final String PIC_LANG_PREFIX = "Sleigh-PIC-";

	private static final int MAX_CASE_SIZE = 32;

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

	private Program program;
	private Listing listing;
	private ReferenceManager refMgr;

	private PseudoDisassembler pseudoDisassembler;
	private AddressSet disassemblyPoints;
	private AddressSet secondPassPoints;

	/**
	 * Constructor for auto-analysis manager.
	 */
	public PicSwitchAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.DISASSEMBLY.after().after().after().after());
	}

	/**
	 * Constructor for private use.
	 * @param program
	 */
	private PicSwitchAnalyzer(Program program) {
		this();
		this.program = program;
		listing = program.getListing();
		refMgr = program.getReferenceManager();
		disassemblyPoints = new AddressSet();
		secondPassPoints = new AddressSet();
		pseudoDisassembler = new PseudoDisassembler(program);
	}

	@Override
	public boolean canAnalyze(Program p) {
		Processor processor = p.getLanguage().getProcessor();
		return (processor == PicProcessor.PROCESSOR_PIC_12 ||
			processor == PicProcessor.PROCESSOR_PIC_16 ||
			processor == PicProcessor.PROCESSOR_PIC_17 || processor == PicProcessor.PROCESSOR_PIC_18);
	}

	@Override
	public boolean getDefaultEnablement(Program p) {
		return true;
	}

	@Override
	public synchronized boolean added(Program p, AddressSetView set, TaskMonitor monitor,
			MessageLog log) {

		this.program = p;
		listing = program.getListing();
		refMgr = program.getReferenceManager();

		disassemblyPoints = new AddressSet();
		secondPassPoints = new AddressSet();

		try {
			pseudoDisassembler = new PseudoDisassembler(program);
			InstructionIterator instrIter = listing.getInstructions(set, true);
			while (instrIter.hasNext()) {
				Instruction instr = instrIter.next();
				if (instr.getFlowType().isJump()) {
					if ("ADDWF".equals(instr.getMnemonicString())) {
						handleAddSwitch(instr);
					}
					else if ("MOVWF".equals(instr.getMnemonicString())) {
						handleAddSwitch(instr);
					}
				}
			}

			performFollowOnAnalysis();
		}
		finally {
			program = null;
			listing = null;
			refMgr = null;
		}

		return true;
	}

	private boolean performFollowOnAnalysis() {
		boolean analysisRequired = false;
		if (!disassemblyPoints.isEmpty()) {
			analysisRequired = true;
			AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
			mgr.disassemble(disassemblyPoints);
		}
		if (!secondPassPoints.isEmpty()) {
			analysisRequired = true;
			AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
			mgr.scheduleOneTimeAnalysis(this, secondPassPoints);
		}
		return analysisRequired;
	}

	public static boolean addSwitch(Instruction instr) {
		PicSwitchAnalyzer analyzer = new PicSwitchAnalyzer(instr.getProgram());
		analyzer.handleAddSwitch(instr);
		return analyzer.performFollowOnAnalysis();
	}

	private void handleAddSwitch(Instruction instr) {

		AddressSet caseRange = new AddressSet();
		int caseNum = 0;
		int caseSize = -1;
		Address instrAddr = instr.getMinAddress();

		boolean caseUpdate = false;
		Reference[] refs =
			program.getReferenceManager().getReferencesFrom(instr.getMinAddress(), Reference.MNEMONIC);
		if (refs.length == 1) { // final case may not have been examined yet
			// Assume that switch should always have 3 or more cases
			return;
		}
		for (Reference ref : refs) {
			if (ref.getReferenceType().isFlow()) {
				caseUpdate = true;
				break;
			}
		}

		AddressSet casePoints = new AddressSet();

		Address caseAddr = instrAddr.add(2);
		while (true) {
			if (caseSize > 0) {
				caseAddr = caseAddr.add(caseSize);
			}
			if (caseUpdate) {
				// Look beyond final case for possible new final case
				if (refMgr.getReference(instr.getMinAddress(), caseAddr, Reference.MNEMONIC) == null) {
					if (listing.getUndefinedDataAt(caseAddr) != null &&
						testDisassmbleFinalCaseAt(caseAddr, caseSize, caseRange)) {
						// Final case
						refMgr.addMemoryReference(instr.getMinAddress(), caseAddr,
							RefType.COMPUTED_JUMP, SourceType.ANALYSIS, Reference.MNEMONIC);
						disassemblyPoints.addRange(caseAddr, caseAddr);
					}
					break;
				}
			}
			else if (refMgr.hasReferencesTo(caseAddr)) {
				break;
			}
			int bytesConsumed = testDisassmbleCaseAt(caseAddr, caseSize);
			if (bytesConsumed == 0) {
				// Check final case which may fall into break code for previous cases
				if (caseNum > 1 && listing.getUndefinedDataAt(caseAddr) != null) {
					// Defer final case check until other cases are disassembled
					secondPassPoints.addRange(instrAddr, instrAddr);
				}
				break;
			}

			++caseNum;
			caseSize = bytesConsumed;
			caseRange.addRange(caseAddr, caseAddr.add(caseSize - 1));

			if (!caseUpdate) {
				casePoints.addRange(caseAddr, caseAddr);
			}
		}

		if (casePoints.getNumAddresses() > 1) {
			AddressIterator caseAddresses = casePoints.getAddresses(true);
			while (caseAddresses.hasNext()) {
				caseAddr = caseAddresses.next();
				refMgr.addMemoryReference(instr.getMinAddress(), caseAddr, RefType.COMPUTED_JUMP,
					SourceType.ANALYSIS, Reference.MNEMONIC);
				disassemblyPoints.addRange(caseAddr, caseAddr);
			}
		}
	}

	/**
	 * Test disassembly of fall-through flow only upto limit if specified.
	 * @param caseAddr
	 * @param caseSize number of contiguous instructions per case or -1 if first case
	 * @return case size or 0 if unsuccessful
	 */
	private int testDisassmbleCaseAt(Address caseAddr, int caseSize) {
		try {
			int byteCnt = 0;
			boolean skip = false;
			while (caseAddr != null) {
				PseudoInstruction instr = pseudoDisassembler.disassemble(caseAddr);
				byteCnt += instr.getLength();
				if (byteCnt > MAX_CASE_SIZE || (caseSize > 0 && byteCnt > caseSize)) {
					return 0; // deviated from expected case size
				}
				caseAddr = instr.getFallThrough();
				if (caseAddr == null && skip) {
					caseAddr = instr.getMinAddress().add(instr.getLength());
				}
				skip = SKIP_INSTRUCTIONS.contains(instr.getMnemonicString());
			}
			if (caseSize <= 0 || byteCnt == caseSize) {
				// return case size if it was unspecified or we had a byteCnt match
				return byteCnt;
			}
		}
		catch (Exception e) {
		}
		return 0;
	}

	private boolean testDisassmbleFinalCaseAt(Address caseAddr, int caseSize, AddressSet caseRange) {
		try {
			int byteCnt = 0;
			boolean skip = false;
			while (caseAddr != null) {
				if (byteCnt != 0 && hasCaseRefTo(caseAddr, caseRange)) {
					return true;
				}
				PseudoInstruction instr = pseudoDisassembler.disassemble(caseAddr);
				byteCnt += instr.getLength();
				if (byteCnt > MAX_CASE_SIZE || (caseSize > 0 && byteCnt > caseSize)) {
					break; // deviated from expected case size
				}
				caseAddr = instr.getFallThrough();
				if (caseAddr == null && skip) {
					caseAddr = instr.getMinAddress().add(instr.getLength());
				}
				skip = SKIP_INSTRUCTIONS.contains(instr.getMnemonicString());
			}
		}
		catch (Exception e) {
			//TODO
		}
		return false;
	}

	private boolean hasCaseRefTo(Address addr, AddressSet caseRange) {
		ReferenceIterator refIter = refMgr.getReferencesTo(addr);
		while (refIter.hasNext()) {
			Reference ref = refIter.next();
			if (caseRange.contains(ref.getFromAddress())) {
				return true;
			}
		}
		return false;
	}

}
