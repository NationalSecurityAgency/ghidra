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
package ghidra.app.plugin.prototype.analysis;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.bookmark.BookmarkEditCmd;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.*;
import ghidra.app.util.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;
import java.util.Iterator;

public class ArmAggressiveInstructionFinderAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "ARM Aggressive Instruction Finder";
	private static final String DESCRIPTION =
		"Aggressively attempt to disassemble ARM/Thumb mixed code.";

	private Program curProgram;
	private Listing listing;

	private int numInstr = 0;
	private boolean addsInfo = false;

	private Register tmodeReg;
	private AddressSet lastBody = null;
	private int lastBodyTheSameCount = 0;
	private PseudoDisassembler pseudo;
	private AddressSet todoSet;

	public ArmAggressiveInstructionFinderAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPrototype();
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after());
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program p) {
		Language language = p.getLanguage();
		return language.getProcessor().equals(Processor.findOrPossiblyCreateProcessor("ARM"));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		this.curProgram = program;
		listing = program.getListing();

		// check executable blocks
		//
		todoSet = checkExecBlocks(program, set);

		tmodeReg = curProgram.getProgramContext().getRegister("TMode");

		lastBody = null;
		lastBodyTheSameCount = 0;

		pseudo = new PseudoDisassembler(program);

		// TODO: get valid function start patterns from function start pattern analyzer

		//First look for ending Pattern between known functions (Alignment) and data before the function
		//Look after each known pattern for function starts first
		//Rinse, repeat.
		//Then go back and do it again.
		//If there are known good function starts, use those.

		monitor.setMessage("ARM AIF " + set.getMinAddress());
		long maxCount = program.getMemory().getExecuteSet().getNumAddresses();
		if (maxCount == 0) {
			maxCount = program.getMemory().getNumAddresses();
		}
		monitor.setMaximum(maxCount);

		// make sure to put on things that are external entry points, but not defined symbols.
		// try disassembling as ARM/THUMB at entry points first
		SymbolTable symbolTable = curProgram.getSymbolTable();
		AddressIterator iter = symbolTable.getExternalEntryPointIterator();
		while (iter.hasNext()) {
			Address entry = iter.next();

			if (monitor.isCancelled()) {
				return true;
			}

			if (!todoSet.contains(entry)) {
				continue;
			}

			Symbol symbol = symbolTable.getPrimarySymbol(entry);
			todoSet.delete(entry, entry);

			if (!symbol.isExternalEntryPoint()) {
				continue;
			}
			else if (doValidStart(entry, monitor)) {
				scheduleFollowOnAnalysis(curProgram, todoSet);
				return true;
			}
		}

		// iterate over undefined blocks, check for a few bytes after the start
		//    Don't do 00 bytes, align correctly
		int numInstChecked = 0;
		int addrCount = 0;
		while (todoSet.isEmpty() == false) {
			
			addrCount++;
			if (addrCount % 256 == 1)
			{
				monitor.setProgress(maxCount - todoSet.getNumAddresses());
			}

			Data data;
			Address minAddr = todoSet.getMinAddress();

			if ((minAddr.getOffset() % 2) != 0) {
				todoSet.delete(minAddr, minAddr);
				continue;
			}
			if (numInstChecked > 4) {
				// jump to the next defined thing, then to next undefined
				numInstChecked = 0;
				CodeUnit cu = listing.getDefinedCodeUnitAfter(minAddr);
				if (cu != null) {
					todoSet.delete(minAddr, cu.getMaxAddress());
					minAddr = cu.getMaxAddress().next();
				} else {
					return true;
				}
			}
			data = listing.getUndefinedDataAt(minAddr);
			if (data == null) {
				numInstChecked = 0;
				todoSet.delete(minAddr, minAddr);
				data = listing.getFirstUndefinedData(todoSet, monitor);
			}
			if (data == null) {
				return true;
			}
			if (todoSet.isEmpty()) {
				return true;
			}

			Address entry = data.getMinAddress();

			if (monitor.isCancelled()) {
				break;
			}

			boolean contains = todoSet.contains(entry);
			todoSet.delete(minAddr, data.getMaxAddress());

			if (contains) {

				boolean isvalid = doValidStart(entry, monitor);

				if (isvalid) {
					scheduleFollowOnAnalysis(program, todoSet);
					return true;
				}
				numInstChecked++;
			}
		}

		// Got here, must be no more to find
		// try to clean up obvious bad bookmarks with clear flow and repair, that might have been caused by bad starts
		//  bad bookmark right above a found code bookmark
		Iterator<Bookmark> biter = curProgram.getBookmarkManager().getBookmarksIterator("Error");
		while (biter.hasNext() && !monitor.isCancelled()) {
			Bookmark bookmark = biter.next();

			Address addr = bookmark.getAddress();
			if (listing.getInstructionAt(addr) != null) {
				continue;
			}

			Bookmark abmark =
				curProgram.getBookmarkManager().getBookmark(addr, "Analysis",
					"ARM Aggressive Instruction Finder");
			if (abmark == null) {
				continue;
			}

			Instruction beforeInstr = listing.getInstructionBefore(addr);
			if (addr.subtract(beforeInstr.getMaxAddress()) < 6) {
				ClearFlowAndRepairCmd cmd = new ClearFlowAndRepairCmd(addr, true, false, true);
				cmd.applyTo(curProgram);
			}
		}

		return true;
	}

	private void scheduleFollowOnAnalysis(Program program, AddressSetView doLaterSet) {
		// Set up a one time analysis to get us back into here if
		//   there are still addresses on the set
		//
		if (!doLaterSet.isEmpty()) {
			AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
			mgr.scheduleOneTimeAnalysis(this, doLaterSet);
		}
	}

	private boolean doValidStart(Address entry, TaskMonitor monitor) {
		BigInteger tmodeVal = null;

		// Try to figure out the right TMode to use
		if (tmodeReg != null) {
			// try to get TMode at last context from the instruction before
			Instruction instr = listing.getInstructionBefore(entry);
			if (instr != null) {
				Address addr = instr.getMinAddress();
				tmodeVal = curProgram.getProgramContext().getValue(tmodeReg, addr, false);
			}
			
			// if instruction doesn't have one set, try to get it from the program
			if (tmodeVal == null) {
				tmodeVal = curProgram.getProgramContext().getValue(tmodeReg, entry, false);
			}
			
			// still no value, start at ARM mode (0)
			if (tmodeVal == null) {
				tmodeVal = BigInteger.ZERO;  
			}
		}
		
		// try the TMode
		boolean isvalid = false;
		try {
			isvalid = checkValidARMTMode(entry, tmodeVal);
		}
		catch (InsufficientBytesException | UnknownInstructionException
				| UnknownContextException e) {
			// ignore, mode not valid
		}

		// try the opposite Thumb mode
		if (!isvalid && tmodeReg != null) {
			tmodeVal = tmodeVal.flipBit(0);
			try {
				isvalid = checkValidARMTMode(entry, tmodeVal);
			}
			catch (InsufficientBytesException | UnknownInstructionException
					| UnknownContextException e) {
				// ignore, not valid
			}
		}
		if (!isvalid) {
			return false;
		}

		numInstr = 0;
		addsInfo = false;

		// if there is an imported symbol at the top of it, assume it adds info
		Symbol sym = curProgram.getSymbolTable().getPrimarySymbol(entry);
		if (sym != null && sym.getSource() == SourceType.IMPORTED) {
			addsInfo = true;
		}
		
		// set the TMode to the mode figured out
		PseudoDisassemblerContext pseudoContext =
				new PseudoDisassemblerContext(curProgram.getProgramContext());
		if (tmodeReg != null) {
			pseudoContext.setValue(tmodeReg, entry, tmodeVal);
		}
		
		// Compute the possibly body, and note any evidence this code is worth
		// taking a risk and disassembling.  It must be consistent with existing code,
		// and add more information, like newly discovered code or a ref to an existing
		// function.
		AddressSet body =
			pseudo.followSubFlows(entry, pseudoContext, 1000, new PseudoFlowProcessor() {
				Object lastResults[] = null;
				Instruction lastInstr = null;
				int duplicateCount = 0;

				@Override
				public boolean followFlows(PseudoInstruction instr) {
					return true;
				}

				@Override
				public boolean process(PseudoInstruction instr) {

					if (instr == null) {
						addsInfo = false;
						return false;
					}

					// don't allow more than 4 duplicate instructions.
					if (lastInstr != null && lastInstr.equals(instr)) {
						duplicateCount++;
						if (duplicateCount > 4) {
							addsInfo = false;
							return false;
						}
					}
					lastInstr = instr;

					numInstr++;
					FlowType ftype = instr.getFlowType();
					if (ftype.isTerminal()) {
						if (!validTerminator(instr)) {
							return false;
						}
						return true;
					}
					// can't follow computed jumps
					if (ftype.isComputed() && ftype.isJump()) {
						return true;
					}
					Address flows[] = instr.getFlows();
					if (flows != null && flows.length > 0) {

						if (!curProgram.getMemory().contains(flows[0])) {
							addsInfo = false;
							return false;
						}

						if (ftype.isJump()) {
							Function func = curProgram.getFunctionManager().getFunctionAt(flows[0]);
							if (func != null) {
								addsInfo = true;
								return false;
							}
						}

						// It must provide calls to other functions to be worthwhile right now.
						// If it doesn't call something else, then it will most likely get called by another
						// function found later.
						if (ftype.isCall()) {
							Function func = curProgram.getFunctionManager().getFunctionAt(flows[0]);
							if (func != null) {
								addsInfo = true;
								if (func.hasNoReturn()) {
									return false;
								}
								return true;
							}
							if (curProgram.getListing().getInstructionAt(flows[0]) == null) {
								addsInfo = true;
								return true;
							}

						}
					}

					// if this is a dynamic call, and the instruction right before it loads into the target register, assume it adds info
					if (ftype.isCall() && ftype.isComputed() && lastResults != null &&
						instr.getNumOperands() == 1) {
						Register reg = instr.getRegister(0);
						if (reg != null) {
							for (int i = 0; i < lastResults.length; i++) {
								if (reg.equals(lastResults[i])) {
									addsInfo = true;
									return true;
								}
							}
						}
					}
					// record last instruction doing a load to a register
					lastResults = null;
					if (instr.getMnemonicString().startsWith("ld")) {
						lastResults = instr.getResultObjects();
					}
					return true;
				}

				private boolean validTerminator(PseudoInstruction instr) {
					// for load multiple, one better be the stack to be a return
					if (instr.getMnemonicString().startsWith("ldm")) {
						Object inObjs[] = instr.getInputObjects();
						if (inObjs != null) {
							for (int i = 0; i < inObjs.length; i++) {
								if (inObjs[i] instanceof Register &&
									(((Register) inObjs[i]).getTypeFlags() & Register.TYPE_SP) == 0) {
									return true;
								}
							}
							return false;
						}
					}
					return true;
				}
			});

		// if this body is a subset of last body, assume we will keep disassembling the same thing since we keep getting the same body
		//
		if (lastBody != null && lastBody.contains(body) && (lastBodyTheSameCount++ > 5)) {
			todoSet.delete(body);
			lastBody = null;
			lastBodyTheSameCount = 0;
		}
		else {
			lastBody = body;
		}

		// don't allow two instruction routines
		if (numInstr <= 2 || !addsInfo) {
			return false;
		}

		// don't allow a very small first block
		if (body.getNumAddressRanges() > 1 && body.getAddressRanges().next().getLength() <= 6) {
			return false;
		}

		// check that body doesn't have any data
		if (listing.getDefinedData(body, true).hasNext()) {
			return false;
		}

		// check that the instruction right before isn't a dynamic jump
		Instruction iBefore = listing.getInstructionBefore(entry);
		if (iBefore != null && iBefore.getMaxAddress().add(1).equals(entry)) {
			FlowType ftype = iBefore.getFlowType();
			if (ftype.isComputed() && ftype.isJump() &&
				curProgram.getReferenceManager().getReferenceCountTo(entry) > 0) {
				// don't try to do anything with the flow from here.
				AddressSet badSet = new AddressSet(body.getMinAddress(), body.getMaxAddress());
				todoSet.delete(badSet);
				return false;
			}
		}

		// check that body isn't all over the place
		AddressRangeIterator riter = body.getAddressRanges();
		long distance = 0;
		Address last = null;
		while (riter.hasNext()) {
			AddressRange range = riter.next();
			if (last != null) {
				distance += Math.abs(last.subtract(range.getMinAddress()));
			}
			last = range.getMaxAddress();
			// don't allow the body range to branch back wards before the entry of this code
			// most valid functions should flow forward
			// we will just hope something else picks this up
			if (range.getMinAddress().subtract(entry) < 0) {
				distance = 0x777777;
				break;
			}
			// TODO: This protects against a jump to a small terminal instruction block
			//       Is this the right way to detect?
			// TODO: If the code flows into other code, it could be branching to it,
			//       which shouldn't be included in the body of the function.
			if (range.getLength() <= 4) {
				distance = 0x777777;
				break;
			}
		}
		if (distance > 4096) {
			return false;
		}

		// check that it doesn't just flow into another routine
		if (curProgram.getListing().getFunctions(body, true).hasNext()) {
			return false;
		}

		monitor.setMessage("ARM AIF : " + entry);

		if (isvalid) {
			try {
				curProgram.getProgramContext().setValue(tmodeReg, entry, entry, tmodeVal);
			}
			catch (ContextChangeException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				return false;
			}
			DisassembleCommand cmd = new DisassembleCommand(entry, null, true);

			int beforeErrorCount = curProgram.getBookmarkManager().getBookmarkCount("Error");
			cmd.applyTo(curProgram);
			int afterErrorCount = curProgram.getBookmarkManager().getBookmarkCount("Error");

			// oops made a mistake somewhere, clear it
			if (beforeErrorCount < afterErrorCount) {
				ClearFlowAndRepairCmd clearCmd =
					new ClearFlowAndRepairCmd(entry, true, false, false);
				clearCmd.applyTo(curProgram);
				return false;
			}
			todoSet.delete(cmd.getDisassembledAddressSet());
			BookmarkEditCmd bcmd =
				new BookmarkEditCmd(entry, BookmarkType.ANALYSIS,
					"ARM Aggressive Intruction Finder", "Found code");
			bcmd.applyTo(curProgram);
			return true;
		}

		return false;
	}

	private boolean checkValidARMTMode(Address entry, BigInteger thumbValue)
			throws InsufficientBytesException, UnknownInstructionException,
			UnknownContextException {
		
		PseudoDisassemblerContext pseudoContext = new PseudoDisassemblerContext(curProgram.getProgramContext());
		
		if (tmodeReg != null && thumbValue != null) {
			pseudoContext.setValue(tmodeReg, entry, thumbValue);
		}
		
		pseudoContext.flowStart(entry);
		PseudoInstruction instr = pseudo.disassemble(entry, pseudoContext, false);
		
		pseudoContext = new PseudoDisassemblerContext(curProgram.getProgramContext());
		pseudoContext.setValue(tmodeReg, entry, thumbValue);

		if (instr != null && !isFillerInstruction(instr)) { 
			return pseudo.checkValidSubroutine(entry, pseudoContext, true, false); // try the current mode
		}
		return false;
	}

	private boolean isFillerInstruction(PseudoInstruction instr) {
		String mnemonic= instr.getMnemonicString();
		
		if (mnemonic.equals("nop")) {
			return true;
		}
		
		if (mnemonic.equals("mov") || mnemonic.equals("movs")) {
			// if input and output register are the same is filler
			if (instr.getNumOperands() == 2) {
				Register reg1 = instr.getRegister(0);
				Register reg2 = instr.getRegister(1);
				if (reg1 != null && reg1.equals(reg2)) {
					return true;
				}
			}
		}
		
		return false;
	}

	/**
	 * Check if there are blocks marked executable.
	 *   If there are exec blocks, remove all un-exec blocks from the set.
	 * @param program program
	 * @param set addresses to be checked
	 * 
	 * @return set of address that are executable
	 */
	private AddressSet checkExecBlocks(Program program, AddressSetView set) {
		// check if there is a block marked unexec

		AddressSet execSet = new AddressSet();
		MemoryBlock blocks[] = program.getMemory().getBlocks();
		for (int i = 0; i < blocks.length; i++) {
			if (blocks[i].isExecute()) {
				execSet.addRange(blocks[i].getStart(), blocks[i].getEnd());
			}
		}

		if (execSet.isEmpty()) {
			return new AddressSet(set);
		}
		if (set.isEmpty()) {
			return execSet;
		}
		return set.intersect(execSet);
	}
}
