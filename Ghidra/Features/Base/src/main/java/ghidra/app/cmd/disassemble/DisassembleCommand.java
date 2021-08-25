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
package ghidra.app.cmd.disassemble;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.disassemble.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Command object for performing disassembly
 */
public class DisassembleCommand extends BackgroundCommand {

	protected AddressSetView startSet;
	protected boolean useDefaultRepeatPatternBehavior = false;

	private AddressSetView restrictedSet;
	private AddressSetView exectuableSet;
	private AddressSet disassembledAddrs;
	private boolean followFlow = true;
	private boolean enableAnalysis = true;
	private DisassemblerContextImpl seedContext;
	private RegisterValue initialContextValue;

	private int alignment; // required instruction alignment for the last doDisassembly
	protected boolean disassemblyPerformed; // if true don't report start problems
	protected String languageError; // non-null to indicate unsupported language
	protected boolean unalignedStart;
	protected boolean nonExecutableStart;

	/**
	 * Constructor for DisassembleCommand.
	 * 
	 * @param start Address to start disassembly.
	 * @param restrictedSet addresses that can be disassembled. a null set implies no restrictions
	 * @param followFlow true means the disassembly should follow flow
	 */
	public DisassembleCommand(Address start, AddressSetView restrictedSet, boolean followFlow) {
		this(new AddressSet(start, start), restrictedSet, followFlow);
		useDefaultRepeatPatternBehavior = true;
	}

	/**
	 * Constructor for DisassembleCommand.
	 * 
	 * @param startSet set of addresses to be the start of a disassembly. The Command object will
	 *            attempt to start a disassembly at each address in this set.
	 * @param restrictedSet addresses that can be disassembled. a null set implies no restrictions
	 */
	public DisassembleCommand(AddressSetView startSet, AddressSetView restrictedSet) {
		this(startSet, restrictedSet, true);
	}

	/**
	 * Constructor for DisassembleCommand.
	 * 
	 * @param startSet set of addresses to be the start of a disassembly. The Command object will
	 *            attempt to start a disassembly at each address in this set.
	 * @param restrictedSet addresses that can be disassembled. a null set implies no restrictions
	 */
	public DisassembleCommand(AddressSetView startSet, AddressSetView restrictedSet,
			boolean followFlow) {
		this("Disassemble", startSet, restrictedSet, followFlow);
	}

	protected DisassembleCommand(String name, AddressSetView startSet, AddressSetView restrictedSet,
			boolean followFlow) {
		super(name, true, true, false);
		this.startSet = startSet;
		this.restrictedSet = restrictedSet;
		this.followFlow = followFlow;
	}

	/**
	 * Allows the disassembler context to be seeded for the various disassembly start points which
	 * may be encountered using the future flow state of the specified seedContext. Any initial
	 * context set via the {@link #setInitialContext(RegisterValue)} method will take precedence
	 * when combined with any seed values. The seedContext should remain unchanged while
	 * disassembler command is actively running.
	 * 
	 * @param seedContext seed context or null
	 */
	public void setSeedContext(DisassemblerContextImpl seedContext) {
		this.seedContext = seedContext;
	}

	/**
	 * Allows a specified initial context to be used at all start points. This value will take
	 * precedence when combined with any individual seed context values specified by the
	 * {@link #setSeedContext(DisassemblerContextImpl)} method. The defaultSeedContext should remain
	 * unchanged while disassembler command is actively running.
	 * 
	 * @param initialContextValue the initial context value to set or null to clear it
	 */
	public void setInitialContext(RegisterValue initialContextValue) {
		if (initialContextValue != null) {
			Register reg = initialContextValue.getRegister();
			initialContextValue = initialContextValue.getRegisterValue(reg.getBaseRegister());
		}
		this.initialContextValue = initialContextValue;
	}

	/**
	 * Set code analysis enablement. By default new instructions will be submitted for
	 * auto-analysis.
	 * 
	 * @param enable
	 */
	public void enableCodeAnalysis(boolean enable) {
		this.enableAnalysis = enable;
	}

	@Override
	public String getStatusMsg() {
		if (disassemblyPerformed) {
			return null;
		}
		if (languageError != null) {
			return "The program's language is not supported: " + languageError;
		}
		if (nonExecutableStart) {
			return "Disassembly of non-executable memory is disabled";
		}
		if (unalignedStart) {
			return "Disassembler requires a start which is " + alignment +
				"-byte aligned and on an undefined code unit";
		}
		return "Disassembler requires a start which is an undefined code unit";
	}

	@Override
	synchronized public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		Program program = (Program) obj;
		return doDisassembly(monitor, program, program.getLanguage().getInstructionAlignment());
	}

	private AddressSetView getExecutableSet(Program program) {
		Memory memory = program.getMemory();
		AddressSet set = new AddressSet();
		for (MemoryBlock block : memory.getBlocks()) {
			if (block.isExecute()) {
				set.add(block.getStart(), block.getEnd());
			}
		}
		return set;
	}

	protected boolean doDisassembly(TaskMonitor monitor, Program program,
			int instructionAlignment) {

		exectuableSet = Disassembler.isRestrictToExecuteMemory(program)
				? exectuableSet = getExecutableSet(program)
				: null;

		this.alignment = instructionAlignment;
		disassemblyPerformed = false;
		unalignedStart = false;
		nonExecutableStart = false;

		disassembledAddrs = new AddressSet();

		Listing listing = program.getListing();

		Disassembler disassembler =
			Disassembler.getDisassembler(program, monitor, new MyListener(monitor));
		disassembler.setSeedContext(seedContext);

		// if no start set, then create one from the start address
		if (startSet == null || startSet.isEmpty()) {
			return true;
		}
		AddressSet set = new AddressSet(startSet);
		if (!useDefaultRepeatPatternBehavior) {
			if (startSet != restrictedSet && !startSet.equals(restrictedSet)) {
				disassembler.setRepeatPatternLimitIgnored(startSet);
			}
			else {
				// If disassembling an exactly specified set, don't truncate zero runs
				disassembler.setRepeatPatternLimit(-1);
			}
		}
		AutoAnalysisManager mgr = null;
		if (enableAnalysis) {
			mgr = AutoAnalysisManager.getAnalysisManager(program);
		}

		long startNumAddr = set.getNumAddresses();
		if (startNumAddr > 1) {
			monitor.initialize(startNumAddr);
		}
		long doneNumAddr = 0;

		AddressSet seedSet = new AddressSet();

		// For each range in the address set to disassemble
		// small ranges get added to the seedSet
		// If a large range is found, then disassemble the seedSet so far, and
		//   process the big range by disassembling flow through the range
		//   causing the analyzer to kick off between disassembly flows
		AddressRangeIterator addressRanges = startSet.getAddressRanges();
		for (AddressRange addressRange : addressRanges) {
			if (monitor.isCancelled()) {
				break;
			}
			// bigger address set
			AddressSet subRangeSet = new AddressSet(addressRange);

			if (startNumAddr > 1) {
				// report on done - number left in this subRange
				monitor.setProgress(doneNumAddr);
			}
			doneNumAddr += subRangeSet.getNumAddresses();  // addresses are only done when disassembled

			while (!subRangeSet.isEmpty() && !monitor.isCancelled()) {
				Address nextAddr = subRangeSet.getMinAddress();

				// Check if location is already on disassembly list
				if (disassembledAddrs.contains(nextAddr)) {
					AddressRange doneRange = disassembledAddrs.getRangeContaining(nextAddr);
					subRangeSet.delete(doneRange);
					continue;
				}

				subRangeSet.delete(nextAddr, nextAddr);

				// detect disassembly started in non-executable initialized block
				if (exectuableSet != null && !exectuableSet.contains(nextAddr) &&
					!program.getMemory().getLoadedAndInitializedAddressSet().contains(nextAddr)) {
					nonExecutableStart = true;
				}

				// only try disassembly on 2 byte boundaries
				if ((nextAddr.getOffset() % alignment) != 0) {
					// Align to the instruction alignment
					//  don't error on align problem here anymore
					// unalignedStart = true;
					nextAddr = nextAddr.subtract(nextAddr.getOffset() % alignment);
				}

				// if range is small, just add it to the seedSet
				long addrsLeft = subRangeSet.getNumAddresses();
				if (addrsLeft <= 4) {
					seedSet.add(nextAddr);
					continue;
				}

				// location to disassemble is not undefined
				Data data = listing.getUndefinedDataAt(nextAddr);
				if (data == null) {
					// set the subRangeSet to undefined data in the subRangeSet
					try {
						AddressSetView undefRanges;
						undefRanges =
							program.getListing().getUndefinedRanges(subRangeSet, true, monitor);
						subRangeSet = new AddressSet(undefRanges);
					}
					catch (CancelledException e) {
						// will get handled below
					}
					continue;
				}

				// process the big range by disassembling flow through the range
				//   causing the analyzer to kick off between disassembly flows
				// disassemble the seedSet first
				doDisassemblySeeds(disassembler, seedSet, mgr);
				seedSet = new AddressSet();

				// do the current start of the subRangeSet
				AddressSet localDisAddrs =
					doDisassemblySeeds(disassembler, new AddressSet(nextAddr), mgr);

				// if anything disassembled, analyze the result set
				analyzeIfNeeded(mgr, subRangeSet, localDisAddrs, monitor);
				subRangeSet.delete(localDisAddrs);

				if (startNumAddr > 1) {
					monitor.setMaximum(startNumAddr);
					// report on done - number left in this subRange, in case large range
					monitor.setProgress(doneNumAddr - subRangeSet.getNumAddresses());
				}
			}
		}

		// If there are any small seedSet ranges left, disassemble them
		//   Don't kick off analysis, that will be done later
		if (!seedSet.isEmpty()) {
			doDisassemblySeeds(disassembler, seedSet, mgr);
		}

		return disassemblyPerformed || (!nonExecutableStart & !unalignedStart);
	}

	/**
	 * Do disassembly of a seedSet of address locations
	 * 
	 * @param disassembler disassembler to use
	 * @param seedSet set of addresses to be disassembled
	 * @param mgr
	 * 
	 * @return addresses actually disassembled
	 */
	protected AddressSet doDisassemblySeeds(Disassembler disassembler, AddressSet seedSet,
			AutoAnalysisManager mgr) {
		AddressSet newDisassembledAddrs =
			disassembler.disassemble(seedSet, restrictedSet, initialContextValue, followFlow);

		if (!newDisassembledAddrs.isEmpty()) {
			disassemblyPerformed = true;
			disassembledAddrs.add(newDisassembledAddrs);

			// notify analysis manager of new code
			if (mgr != null) {
				mgr.codeDefined(newDisassembledAddrs);
			}
		}

		return newDisassembledAddrs;
	}

	/**
	 * Determine if intermediate analysis is required to reduce the risk of disassembling data
	 * regions when performing static disassembly over a contiguous range if addresses. This method
	 * attemps to identify this situation by checking the first range of disassembledSet against the
	 * startSet. Analysis will be triggered if startSet contains both the max address of the first
	 * range of disassembledSet (M where M=disassembledSet.firstRange().getMaxAddress()) and the
	 * next address (M.next()) which will be the next seed point.
	 * 
	 * @param mgr auto analysis manager or null if analysis disabled
	 * @param startSet disassembly seed points (prior to removing disassembledSet)
	 * @param disassembledSet last set of disassembled addresses using startSet min-address as seed
	 *            point
	 */
	private static void analyzeIfNeeded(AutoAnalysisManager mgr, AddressSetView startSet,
			AddressSetView disassembledSet, TaskMonitor monitor) {
		if (disassembledSet == null || disassembledSet.isEmpty()) {
			return;
		}

		if (mgr == null || monitor.isCancelled()) {
			return;
		}

		AddressRange firstRange = disassembledSet.getFirstRange();
		Address rangeEnd = firstRange.getMaxAddress();
		Address nextAddr = rangeEnd.next();
		if (nextAddr != null && startSet.contains(rangeEnd) && startSet.contains(nextAddr)) {
			mgr.startAnalysis(monitor, false);
		}
	}

	/**
	 * Returns an address set of all instructions that were disassembled.
	 * 
	 * @return an address set of all instructions that were disassembled
	 */
	public AddressSet getDisassembledAddressSet() {
		return disassembledAddrs;
	}

//	private void copyContext(Address from, Address to) {
//		ProgramContext context = program.getProgramContext();
//		Register[] regs = context.getProcessorStateRegisters();
//		for(int i=0;i<regs.length;i++) {
//			BigInteger value = context.getValue(regs[i], from, false);
//			context.setValue(regs[i], to, to, value);
//		}
//
//	}

	private class MyListener implements DisassemblerMessageListener {
		private TaskMonitor monitor;

		MyListener(TaskMonitor monitor) {
			this.monitor = monitor;
		}

		@Override
		public void disassembleMessageReported(String msg) {
			//TODO: Why is this ever null?
			if (monitor != null) {
				monitor.setMessage(msg);
			}
		}
	}

	/*
	private AddressSet listToSet(ArrayList list) {
		AddressSet set = new AddressSet(program.getAddressFactory());
		Iterator iter = list.iterator();
		while (iter.hasNext()) {
			Address addr = (Address) iter.next();
			set.addRange(addr, addr);
		}
		return set;
	}
	*/
}
