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
/*
 *  Aggressive code Finder.
 *
 *  Looks at all undefined bytes to see if it starts a valid subroutine.
 *  If it does, it will disassemble it, schedule itself to run again,
 *  and then return so that other auto analysis can run.
 */
package ghidra.app.plugin.prototype.analysis;

import java.math.BigInteger;
import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.bookmark.BookmarkEditCmd;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger.SleighDebugMode;
import ghidra.app.services.*;
import ghidra.app.util.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class AggressiveInstructionFinderAnalyzer extends AbstractAnalyzer {

	private static final int MINIMUM_FUNCTION_COUNT = 20;

	private static final String NAME = "Aggressive Instruction Finder";
	private static final String DESCRIPTION =
		"Finds valid code in undefined bytes that have not been disassembled.\n" +
			"WARNING: This should not be run unless good code has already been found.\n" +
			"YOU MUST CHECK THE RESULTS, IT MAY CREATE A LOT OF BAD CODE!";

	private static final String OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks";
	private static final String OPTION_DESCRIPTION_CREATE_BOOKMARKS =
		"If checked, an alaysis bookmark will be created at the start of each disassembly " +
			"location where a run of instructions are identified by this analyzer.";
	private static final boolean OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED = true;

	private boolean createBookmarksEnabled = OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED;

	private Program curProgram;
	private Listing listing;

	private int numInstr = 0;
	private boolean addsInfo = false;

	private HashMap<BigInteger, Integer> funcStartMap;
	private HashMap<BigInteger, RegisterValue> funcStartContext;

	private long lastProgramHash;
	private long lastFuncCount = 0;

	public AggressiveInstructionFinderAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPrototype();
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after());
		setDefaultEnablement(false);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		this.curProgram = program;
		listing = program.getListing();

		// check executable blocks
		//
		set = checkExecBlocks(program, set);

		PseudoDisassembler pseudo = new PseudoDisassembler(program);

		long alignment = program.getLanguage().getInstructionAlignment();

		long funcCount = program.getFunctionManager().getFunctionCount();
		if (funcCount < MINIMUM_FUNCTION_COUNT || program.getListing().getNumInstructions() <= 0) {
			log.appendMsg("AggressiveInstructionFinder",
				"Aggressive Instruction Finder Not Run.  Too few functions defined for proper analysis!");
			return true;
		}
		if (funcStartMap == null || lastProgramHash != program.hashCode() ||
			funcStartMap.isEmpty() || funcCount > (lastFuncCount * 1.10)) {
			lastProgramHash = program.hashCode();
			lastFuncCount = funcCount;
			monitor.setMessage("AIF - hashing functions");

			funcStartMap = new HashMap<>();
			funcStartContext = new HashMap<>();
			FunctionManager functionManager = program.getFunctionManager();
			FunctionIterator funcs = functionManager.getFunctions(true);
			int functionCount = functionManager.getFunctionCount();
			monitor.initialize(functionCount);

			while (funcs.hasNext()) {
				monitor.incrementProgress(1);
				Function function = funcs.next();

				Address entry = function.getEntryPoint();

				Instruction instr = program.getListing().getInstructionAt(entry);

				RegisterValue disContext = program.getProgramContext().getDisassemblyContext(entry);

				if (instr == null) {
					continue;
				}
				try {
					SleighDebugLogger ilog =
						new SleighDebugLogger(program, entry, SleighDebugMode.MASKS_ONLY);
					if (ilog.parseFailed()) {
						continue;
					}
					byte[] imask = ilog.getInstructionMask();
					if (imask.length == 1) {
						imask[0] = (byte) 0xff;
					}
					byte[] ibytes = ilog.getMaskedBytes(imask);

					instr = program.getListing().getInstructionAt(instr.getMaxAddress().add(1));
					if (instr != null) {
						ilog = new SleighDebugLogger(program, entry.add(ibytes.length),
							SleighDebugMode.MASKS_ONLY);
						byte[] imask2 = ilog.getInstructionMask();
						if (imask2.length == 1) {
							imask2[0] = (byte) 0xff;
						}
						byte[] ibytes2 = ilog.getMaskedBytes(imask2);
						byte[] ibytes1 = ibytes;
						ibytes = new byte[ibytes1.length + ibytes2.length];
						System.arraycopy(ibytes1, 0, ibytes, 0, ibytes1.length);
						System.arraycopy(ibytes2, 0, ibytes, ibytes1.length, ibytes2.length);
					}

					BigInteger bi = new BigInteger(ibytes);
					Integer count = funcStartMap.get(bi);
					if (count != null) {
						count++;
						funcStartMap.put(bi, count);
						continue;
					}
					funcStartMap.put(bi, 1);
					funcStartContext.put(bi, disContext);
				}
				catch (IllegalStateException exc) {
					continue;
				}
				catch (IllegalArgumentException exc) {
					continue;
				}
			}
//			Err.info(this, "" + funcList.size() + " number of starts");
//
//			Iterator iter = funcStartMap.keySet().iterator();
//			while (iter.hasNext()) {
//				BigInteger key = (BigInteger) iter.next();
//				Integer val = funcStartMap.get(key);
//				Err.info(this, "   " + key + " = " + val + "\t\t\t\t");
//			}
		}

		monitor.setMessage("Aggressive Instruction Finder");
		long startAddressCount = set.getNumAddresses();
		monitor.initialize(startAddressCount);

		Collection<RegisterValue> contextStarts = funcStartContext.values();
		HashSet<RegisterValue> contextSet = new HashSet<>();
		contextSet.addAll(contextStarts);

		// get an instruction iterator
		long count = 0;
		while (set.isEmpty() == false) {
			long currentAddressCount = set.getNumAddresses();
			monitor.setProgress(startAddressCount - currentAddressCount);

			Data data;
			Address minAddr = set.getMinAddress();

			data = listing.getUndefinedDataAt(minAddr);
			if (data == null) {
				set = set.subtract(new AddressSet(minAddr, minAddr));
				data = listing.getFirstUndefinedData(set, monitor);
			}
			if (data == null) {
				return true;
			}

			count++;
			if ((count % 4000) == 0) {
				monitor.setMessage("AIF - " + minAddr);
			}

			Address entry = data.getMinAddress();
			if (monitor.isCancelled()) {
				break;
			}

			Address maxAddr = data.getMaxAddress();
			// align the maxAddr to the alignment of the code
			if (alignment > 1) {
				maxAddr = maxAddr.add((alignment - 1) - ((maxAddr.getOffset() % alignment)));
			}
			AddressSet subSet = new AddressSet(set.getMinAddress(), maxAddr);

			boolean contains = set.contains(entry);
			set = set.subtract(subSet);

			try {
				RegisterValue disContext = null;

				if (contains) {
					// check start, if no other function starts like this, don't do it!
					Integer startCount = 0;
					boolean isvalid = false;
					Iterator<RegisterValue> contextIter = contextSet.iterator();
					while (contextIter.hasNext()) {
						disContext = contextIter.next();
						try {
							PseudoDisassemblerContext pseudoContext =
								new PseudoDisassemblerContext(program.getProgramContext());
							if (disContext != null) {
								pseudoContext.flowStart(entry);
								pseudoContext.setRegisterValue(disContext);
							}
							SleighDebugLogger ilog = new SleighDebugLogger(
								new MemoryBufferImpl(program.getMemory(), entry), pseudoContext,
								program.getLanguage(), SleighDebugMode.MASKS_ONLY);
							if (ilog.parseFailed()) {
								continue;
							}
							byte[] imask = ilog.getInstructionMask();
							if (imask.length == 1) {
								imask[0] = (byte) 0xff;
							}
							byte[] ibytes = ilog.getMaskedBytes(imask);

							Address nextEntryAddr = entry.add(ibytes.length);
							ilog = new SleighDebugLogger(
								new MemoryBufferImpl(program.getMemory(), nextEntryAddr),
								pseudoContext, program.getLanguage(), SleighDebugMode.MASKS_ONLY);

							byte[] imask2 = ilog.getInstructionMask();
							if (imask2.length == 1) {
								imask2[0] = (byte) 0xff;
							}
							byte[] ibytes2 = ilog.getMaskedBytes(imask2);
							byte[] ibytes1 = ibytes;
							ibytes = new byte[ibytes1.length + ibytes2.length];
							System.arraycopy(ibytes1, 0, ibytes, 0, ibytes1.length);
							System.arraycopy(ibytes2, 0, ibytes, ibytes1.length, ibytes2.length);

							BigInteger bi = new BigInteger(ibytes);
							startCount = funcStartMap.get(bi);
							if (startCount == null) {
								continue;
							}
							if (startCount < 4) {
								continue;
							}
							RegisterValue possibleDisContext = funcStartContext.get(bi);
							if (!possibleDisContext.equals(disContext)) {
								continue;
							}
						}
						catch (IllegalStateException exc) {
							continue;
						}

						PseudoDisassemblerContext pseudoContext =
							new PseudoDisassemblerContext(program.getProgramContext());
						if (disContext != null) {
							pseudoContext.setValue(disContext.getRegister(), entry,
								disContext.getUnsignedValueIgnoreMask());
						}
						isvalid = pseudo.checkValidSubroutine(entry, pseudoContext, true, false);
						//isvalid = pseudo.isValidSubroutine(entry);
						if (isvalid) {
							break;
						}
					}
					if (isvalid == false) {
						continue;
					}

					// Pseudo Disassemble to figure out if this is a good function start

					numInstr = 0;
					addsInfo = false;
					PseudoDisassemblerContext pseudoContext =
						new PseudoDisassemblerContext(program.getProgramContext());
					if (disContext != null) {
						pseudoContext.setValue(disContext.getRegister(), entry,
							disContext.getUnsignedValueIgnoreMask());
						//pseudoContext.flowStart(entry);
						//pseudoContext.setRegisterValue(disContext);
					}

					AddressSet body = pseudo.followSubFlows(entry, pseudoContext, 4000,
						new PseudoFlowProcessor() {
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
								numInstr++;
								FlowType ftype = instr.getFlowType();
								if (ftype.isTerminal()) {
									return true;
								}
								Address flows[] = instr.getFlows();
								if (flows != null && flows.length > 0) {

									if (!curProgram.getMemory().contains(flows[0])) {
										addsInfo = false;
										return false;
									}

									// calls always add info
									if (ftype.isCall()) {
										addsInfo = true;
										//								if (curProgram.getFunctionManager().getFunctionAt(flows[0]) != null) {
										//									addsInfo = true;
										//								}
									}

									// jumps must jump to existing code.
									if (ftype.isJump()) {
										if (listing.getInstructionAt(flows[0]) != null) {
											addsInfo = true;
										}
									}
								}
								return true;
							}
						});

					// don't allow two instruction routines
					// if the routine doesn't add good info, it must start like a large numbe of other functions
					if (numInstr <= 2 || (!addsInfo && startCount < 50)) {
						continue;
					}

					// check that body doesn't have any data
					if (listing.getDefinedData(body, true).hasNext()) {
						continue;
					}

					monitor.setMessage("Aggressive Instruction Finder : " + entry);

					if (isvalid) {
						program.getProgramContext().setRegisterValue(entry, entry, disContext);
						DisassembleCommand cmd = new DisassembleCommand(entry, null, true);
						cmd.applyTo(program);
						set = set.subtract(cmd.getDisassembledAddressSet());
						if (createBookmarksEnabled) {
							BookmarkEditCmd bcmd = new BookmarkEditCmd(entry, BookmarkType.ANALYSIS,
								"Aggressive Intruction Finder", "Found code");
							bcmd.applyTo(program);
						}
						break;
					}
				}
			}
			catch (Exception e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
		}

		// Set up a one time analysis to get us back into here if
		// there are still addresses on the set
		//
		if (!set.isEmpty()) {
			AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
			mgr.scheduleOneTimeAnalysis(this, set);
		}
		return true;
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
		for (MemoryBlock block : blocks) {
			if (block.isExecute()) {
				execSet.addRange(block.getStart(), block.getEnd());
			}
		}

		if (execSet.isEmpty()) {
			return set;
		}
		return set.intersect(execSet);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled, null,
			OPTION_DESCRIPTION_CREATE_BOOKMARKS);

	}

	@Override
	public void optionsChanged(Options options, Program program) {
		createBookmarksEnabled =
			options.getBoolean(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled);
	}
}
