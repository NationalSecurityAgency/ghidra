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

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;

public class HexagonUnsupportSemanticAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Hexagon Unsupported Semantic Check";
	private static final String DESCRIPTION =
		"Detects and bookmarks instruction packets which read a predicate register before it is written";

	private final static String PROCESSOR_NAME = "Hexagon";
	private final static String BOOKMARK_CATEGORY_NAME = "Unsupported Semantics";

	private static final String[] predicateNames = new String[] { "P0", "P1", "P2", "P3" };

	private Register packetOffsetRegister;

	private HashSet<Register> pNewRegisters = new HashSet<Register>();

	public HexagonUnsupportSemanticAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.CODE_ANALYSIS);
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!PROCESSOR_NAME.equals(program.getLanguage().getProcessor().toString())) {
			return false;
		}

		packetOffsetRegister = program.getRegister("packetOffset");

		for (int i = 0; i < predicateNames.length; i++) {
			Register predReg = program.getRegister(predicateNames[i] + ".new");
			pNewRegisters.add(predReg);
		}

		return true;
	}

	private boolean isStartOfPacket(Instruction instruction) {
		BigInteger value = instruction.getValue(packetOffsetRegister, false);
		return value == null || (value.intValue() == 0);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		for (AddressRange range : set) {
			added(program, range.getMinAddress(), range.getMaxAddress(), monitor, log);
		}
		return true;
	}

	private Address getStartOfPacket(Program program, Address instrAddr) {
		Listing listing = program.getListing();
		// assume we will only get aligned address
		Instruction instr = listing.getInstructionAt(instrAddr);
		try {
			while (instr != null && !isStartOfPacket(instr)) {
				Address prevAddr = instrAddr.subtractNoWrap(4);
				instr = listing.getInstructionAt(prevAddr);
				if (instr != null) {
					instrAddr = instr.getAddress();
				}
			}
		}
		catch (AddressOverflowException e) {
			// ignore
		}
		return instrAddr;
	}

	private int getPredicateNumber(Register preg) {
		return preg.getName().charAt(1) - 0x30;
	}

	private void added(Program program, Address minAddr, Address maxAddr, TaskMonitor monitor,
			MessageLog log) {

		Listing listing = program.getListing();

		boolean[] predWasWritten = new boolean[predicateNames.length];
		Arrays.fill(predWasWritten, false);

		Address instrAddr = getStartOfPacket(program, minAddr); // find start of packet
		Instruction instr = listing.getInstructionAt(instrAddr);

		// skip past empty regions
		if (instr == null) {
			instr = listing.getInstructionAfter(instrAddr);
			if (instr == null) {
				return;
			}
		}
		instrAddr = instr.getAddress();

		while (instr != null && (instrAddr.compareTo(maxAddr) <= 0 || !isStartOfPacket(instr))) {

			if (isStartOfPacket(instr)) {
				Arrays.fill(predWasWritten, false);
			}

			for (PcodeOp op : instr.getPcode()) {
				for (Varnode in : op.getInputs()) {
					if (in.isRegister() && in.getSize() == 1) {
						Register reg = program.getRegister(in.getAddress(), 1);
						if (pNewRegisters.contains(reg)) {
							int index = getPredicateNumber(reg);
							if (!predWasWritten[index]) {
								markUnsupportPredicateRead(instr, reg);
							}
						}
					}
				}
				Varnode out = op.getOutput();
				if (out != null && out.isRegister() && out.getSize() == 1) {
					Register reg = program.getRegister(out.getAddress(), 1);
					if (pNewRegisters.contains(reg)) {
						// We ignore write to P3P0_ since this should only occur for packet initialization
						int index = getPredicateNumber(reg);
						predWasWritten[index] = true;
					}
				}
			}

			try {
				instrAddr = instrAddr.addNoWrap(4);
			}
			catch (AddressOverflowException e) {
				break;
			}
			instr = listing.getInstructionAt(instrAddr);

			if (instr == null) {
				// skip past empty regions
				instr = listing.getInstructionAfter(instrAddr);
				if (instr != null) {
					instrAddr = instr.getAddress();
					Arrays.fill(predWasWritten, false);
				}
			}

		}

	}

	private void markUnsupportPredicateRead(Instruction instr, Register predReg) {
		instr.getProgram().getBookmarkManager().setBookmark(instr.getAddress(),
			BookmarkType.WARNING, BOOKMARK_CATEGORY_NAME,
			"Predicate " + predReg.getName() + " read before written");
	}

	@Override
	public boolean removed(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		program.getBookmarkManager().removeBookmarks(set, BookmarkType.WARNING,
			BOOKMARK_CATEGORY_NAME, monitor);
		return true;
	}
}
