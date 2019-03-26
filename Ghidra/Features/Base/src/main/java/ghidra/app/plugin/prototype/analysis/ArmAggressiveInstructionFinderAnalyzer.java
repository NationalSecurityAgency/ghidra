/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
	private AddressSetView todoSet;

//	private HashMap<BigInteger, Integer> funcStartMap;
//	private HashMap<BigInteger, BigInteger> tmodeStartMap;
//	private long lastProgramHash;
//	private long lastFuncCount = 0;

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

		//Gather up all patterns for current functions starts
//		computeExistingMasks(monitor);

//		AddressSet followingStarts = findStartsAfterFunctions();

		//First look for ending Pattern between known functions (Alignment) and data before the function
		//Look after each known pattern for function starts first
		//Rinse, repeat.
		//Then go back and do it again.
		//If there are known good function starts, use those.

		monitor.setMessage("ARM AIF " + set.getMinAddress());

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
			AddressSet subSet = new AddressSet(entry, entry);
			todoSet = todoSet.subtract(subSet);

			if (!symbol.isExternalEntryPoint()) {
				continue;
			}
			else if (doValidStart(entry, monitor)) {
				scheduleFollowOnAnalysis(curProgram, todoSet);
				return true;
			}
		}

		// get an instruction iterator
		while (todoSet.isEmpty() == false) {

			Data data;
			Address minAddr = todoSet.getMinAddress();

			if ((minAddr.getOffset() % 2) != 0) {
				todoSet = todoSet.subtract(new AddressSet(minAddr, minAddr));
				continue;
			}
			data = listing.getUndefinedDataAt(minAddr);
			if (data == null) {
				todoSet = todoSet.subtract(new AddressSet(minAddr, minAddr));
				data = listing.getFirstUndefinedData(todoSet, monitor);
			}
			if (data == null) {
				return true;
			}

			Address entry = data.getMinAddress();

			if (monitor.isCancelled()) {
				break;
			}

			AddressSet subSet = new AddressSet(todoSet.getMinAddress(), data.getMaxAddress());

			boolean contains = todoSet.contains(entry);
			todoSet = todoSet.subtract(subSet);

			if (contains) {

				boolean isvalid = doValidStart(entry, monitor);

				if (isvalid) {
					scheduleFollowOnAnalysis(program, todoSet);
					return true;
				}
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
		// try the mode of the last instruction above this place

		BigInteger curValue = null;
		PseudoDisassemblerContext pseudoContext =
			new PseudoDisassemblerContext(curProgram.getProgramContext());

		// get the current value from the program context
		curValue = curProgram.getProgramContext().getValue(tmodeReg, entry, false);
		// if it doesn't have one set, try to get it the last context from the instruction before
		if (curValue == null) {
			Instruction instr = listing.getInstructionBefore(entry);
			if (instr != null) {
				curValue =
					curProgram.getProgramContext().getValue(tmodeReg, instr.getMinAddress(), false);
				if (curValue != null) {
					pseudoContext.setValue(tmodeReg, entry, curValue);
				}
			}
		}
		boolean isvalid = pseudo.checkValidSubroutine(entry, pseudoContext, true, false); // try the current mode

		if (!isvalid && tmodeReg != null) {
			// TMode is single bit value
			if (curValue != null) {
				curValue = curValue.flipBit(0);
			}
			else {
				curValue = BigInteger.ONE;
			}

			pseudoContext = new PseudoDisassemblerContext(curProgram.getProgramContext());
			pseudoContext.setValue(tmodeReg, entry, curValue);

			isvalid = pseudo.checkValidSubroutine(entry, pseudoContext, true, false);

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
		pseudoContext = new PseudoDisassemblerContext(curProgram.getProgramContext());
		pseudoContext.setValue(tmodeReg, entry, curValue);
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
						for (int i = 0; i < lastResults.length; i++) {
							if (reg.equals(lastResults[i])) {
								addsInfo = true;
								return true;
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
			todoSet = todoSet.subtract(body);
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
				todoSet = todoSet.subtract(badSet);
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
				curProgram.getProgramContext().setValue(tmodeReg, entry, entry, curValue);
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
			todoSet = todoSet.subtract(cmd.getDisassembledAddressSet());
			BookmarkEditCmd bcmd =
				new BookmarkEditCmd(entry, BookmarkType.ANALYSIS,
					"ARM Aggressive Intruction Finder", "Found code");
			bcmd.applyTo(curProgram);
			return true;
		}

		return false;
	}

	/**
	 * Check if there are blocks marked executable.
	 *   If there are exec blocks, remove all un-exec blocks from the set.
	 * @param program
	 * @param set
	 */
	private AddressSetView checkExecBlocks(Program program, AddressSetView set) {
		// check if there is a block marked unexec

		AddressSet execSet = new AddressSet();
		MemoryBlock blocks[] = program.getMemory().getBlocks();
		for (int i = 0; i < blocks.length; i++) {
			if (blocks[i].isExecute()) {
				execSet.addRange(blocks[i].getStart(), blocks[i].getEnd());
			}
		}

		if (execSet.isEmpty()) {
			return set;
		}
		if (set.isEmpty()) {
			return execSet;
		}
		return set.intersect(execSet);
	}

//	private boolean computeExistingMasks(TaskMonitor monitor) {
//		long funcCount = curProgram.getFunctionManager().getFunctionCount();
//		
//		if (funcStartMap == null || lastProgramHash != curProgram.hashCode() ||
//				funcStartMap.isEmpty() || funcCount > (lastFuncCount * 1.10)) {
//				lastProgramHash = curProgram.hashCode();
//				lastFuncCount = funcCount;
//				
//				funcStartMap = new HashMap<BigInteger, Integer>();
//		}
//		
//		if (funcCount < 20 || curProgram.getListing().getNumInstructions() <= 0) {
//			return false;
//		}
//		
//		monitor.setMessage("AIF - hashing functions");
//		
//		FunctionManager functionManager = curProgram.getFunctionManager();
//		FunctionIterator funcs = functionManager.getFunctions(true);
//		int functionCount = functionManager.getFunctionCount();
//		monitor.initialize(functionCount);
//
//		while (funcs.hasNext()) {
//			monitor.incrementProgress(1);
//			Function function = funcs.next();
//
//			Address entry = function.getEntryPoint();
//
//			// get the current value from the program context
//			BigInteger tmodeVal = curProgram.getProgramContext().getValue( tmodeReg, entry, false);
//			
//			Instruction instr = curProgram.getListing().getInstructionAt(entry);
//			if (instr == null) {
//				continue;
//			}
//			try {
//				SleighDebugLogger ilog =
//					new SleighDebugLogger(curProgram, entry, SleighDebugMode.MASKS_ONLY);
//				if (ilog.parseFailed()) {
//					continue;
//				}
//				byte[] imask = ilog.getInstructionMask();
//				if (imask.length == 1) {
//					imask[0] = (byte) 0xff;
//				}
//				byte[] ibytes = ilog.getMaskedBytes(imask);
//				int ilen = instr.getLength();
//
//				instr = curProgram.getListing().getInstructionAt(instr.getMaxAddress().add(1));
//				if (instr != null) {
//					ilog =
//						new SleighDebugLogger(curProgram, entry.add(ibytes.length),
//							SleighDebugMode.MASKS_ONLY);
//					byte[] imask2 = ilog.getInstructionMask();
//					if (imask2.length == 1) {
//						imask2[0] = (byte) 0xff;
//					}
//					byte[] ibytes2 = ilog.getMaskedBytes(imask2);
//					byte[] ibytes1 = ibytes;
//					ibytes = new byte[ibytes1.length + ibytes2.length];
//					System.arraycopy(ibytes1, 0, ibytes, 0, ibytes1.length);
//					System.arraycopy(ibytes2, 0, ibytes, ibytes1.length, ibytes2.length);
//				}
//
//				BigInteger bi = new BigInteger(ibytes);
//				Integer count = funcStartMap.get(bi);
//				if (count != null) {
//					count++;
//					funcStartMap.put(bi, count);
//					// tmodeStartMap.put(bi, tmodeVal);
//					continue;
//				}
//				funcStartMap.put(bi, 1);
//				//tmodeStartMap.put(bi, tmodeVal);
//			}
//			catch (IllegalStateException exc) {
//				continue;
//			}
//			catch (IllegalArgumentException exc) {
//				continue;
//			}
//		}
////			Err.info(this, "" + funcList.size() + " number of starts");
////			
////			Iterator iter = funcStartMap.keySet().iterator();
////			while (iter.hasNext()) {
////				BigInteger key = (BigInteger) iter.next();
////				Integer val = funcStartMap.get(key);
////				Err.info(this, "   " + key + " = " + val + "\t\t\t\t");
////			}
//		
//		return true;
//	}

}
