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
package ghidra.program.disassemble;

import java.lang.reflect.Constructor;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.RepeatInstructionByteTracker;
import ghidra.framework.options.Options;
import ghidra.program.database.register.AddressRangeObjectMap;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.lang.InstructionError.InstructionErrorType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.AbstractProgramContext;
import ghidra.program.util.ProgramContextImpl;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Class to perform disassembly.  Contains the logic to follow instruction
 * flows to continue the disassembly.
 * 17-Nov-2008: moved to ghidra.program.disassemble package since this is now used during 
 * 					      language upgrades which may occur during construction of ProgramDB.
 * 12-Dec-2012: major refactor of disassembly to perform bulk add of instructions to 
 * program to avoid context related conflicts
 */
public class Disassembler implements DisassemblerConflictHandler {

	private static final int DISASSEMBLE_MEMORY_CACHE_SIZE = 8;

	/**
	 * <code>MARK_BAD_INSTRUCTION_PROPERTY</code> Program Disassembler property 
	 * enables marking of instruction disassembly errors.  Boolean property is defined
	 * within the Disassembler property list, see {@link Program#DISASSEMBLER_PROPERTIES}.
	 */
	public static final String MARK_BAD_INSTRUCTION_PROPERTY = "Mark Bad Disassembly";

	/**
	 * <code>MARK_UNIMPL_PCODE_PROPERTY</code> Program Disassembler property 
	 * enables marking of instructions which are missing their pcode implementation.  
	 * Boolean property is defined within the Disassembler property list, see 
	 * {@link Program#DISASSEMBLER_PROPERTIES}.
	 */
	public static final String MARK_UNIMPL_PCODE_PROPERTY = "Mark Unimplemented Pcode";

	/**
	 * <code>RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY</code> Program Disassembler property 
	 * restricts disassembly to executable memory only.  
	 * Boolean property is defined within the Disassembler property list, see 
	 * {@link Program#DISASSEMBLER_PROPERTIES}.
	 */
	public static final String RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY =
		"Restrict Disassembly to Executable Memory";

	public static final String ERROR_BOOKMARK_CATEGORY = "Bad Instruction";
	public static final String UNIMPL_BOOKMARK_CATEGORY = "Unimplemented Pcode";

	public static final int MAX_REPEAT_PATTERN_LENGTH = 16;

	private final static int NUM_ADDRS_FOR_NOTIFICATION = 1024;
	private final static int INSTRUCTION_SET_SIZE_LIMIT = 2048;

	protected final Language language;
	protected final AddressFactory addrFactory;
	protected final Register baseContextRegister;
	protected final ParallelInstructionLanguageHelper parallelHelper; // may be null

	private Program program;

	private DisassemblerContextImpl seedContext; // provides seed context for new flows
	private DisassemblerMessageListener listener;
	private AddressSetView restrictedAddressSet;
	private AddressSetView initializedAddressSet;
	private TaskMonitor monitor;

	private ProgramContext realProgramContext;
	private ProgramContextImpl defaultLanguageContext; // used if program is null (future use)

	protected DisassemblerProgramContext disassemblerProgramContext; // proxy context which contains in-progress disassembly context
	protected DisassemblerContextImpl disassemblerContext;

	int instAlignment;

	private DisassemblerQueue disassemblerQueue;

	private Listing listing;
	private int disassembleCount;
	private int totalCount;
	private RepeatInstructionByteTracker repeatInstructionByteTracker =
		new RepeatInstructionByteTracker(MAX_REPEAT_PATTERN_LENGTH, null);

	protected BookmarkManager bmMgr;
	//private boolean restrictToExecuteMemory = false;
	protected boolean doMarkBadInstructions = true;
	private boolean doMarkUnimplPcode = true;
	private int instructionSetSizeLimit = INSTRUCTION_SET_SIZE_LIMIT;

	private boolean followFlow = false;

	/**
	 * Get a suitable disassembler instance. 
	 * Marking of bad instructions honors "Mark Bad Disassembly" 
	 * program Disassembler option.
	 * @param program the program to be disassembled.
	 * @param monitor progress monitor
	 * @param listener object to notify of disassembly messages.
	 * @return a disassembler ready to disassemble
	 */
	public static Disassembler getDisassembler(Program program, TaskMonitor monitor,
			DisassemblerMessageListener listener) {
		Class<? extends Disassembler> disassemblerClass =
			getLanguageSpecificDisassembler(program.getLanguage());
		if (disassemblerClass != null) {
			try {
				Constructor<? extends Disassembler> constructor = disassemblerClass.getConstructor(
					Program.class, TaskMonitor.class, DisassemblerMessageListener.class);
				return constructor.newInstance(program, monitor, listener);
			}
			catch (Exception e) {
				throw new RuntimeException("Disassembler instantiation failure " +
					GhidraLanguagePropertyKeys.CUSTOM_DISASSEMBLER_CLASS + " (" +
					disassemblerClass.getName() + "): " +
					program.getLanguage().getLanguageDescription().getLanguageID(), e);
			}
		}
		return new Disassembler(program, monitor, listener);
	}

	/**
	 * Get a suitable disassembler instance.
	 * Intended for block pseudo-disassembly use only when the method 
	 * {@link Disassembler#pseudoDisassembleBlock(MemBuffer, RegisterValue, int)}
	 * is used.
	 * @param language processor language
	 * @param addrFactory address factory 
	 * @param monitor progress monitor
	 * @param listener object to notify of disassembly messages.
	 * @return a disassembler ready to disassemble
	 */
	public static Disassembler getDisassembler(Language language, AddressFactory addrFactory,
			TaskMonitor monitor, DisassemblerMessageListener listener) {
		Class<? extends Disassembler> disassemblerClass = getLanguageSpecificDisassembler(language);
		if (disassemblerClass != null) {
			try {
				Constructor<? extends Disassembler> constructor =
					disassemblerClass.getConstructor(Language.class, AddressFactory.class,
						TaskMonitor.class, DisassemblerMessageListener.class);
				return constructor.newInstance(language, addrFactory, monitor, listener);
			}
			catch (Exception e) {
				throw new RuntimeException("Disassembler instantiation failure " +
					GhidraLanguagePropertyKeys.CUSTOM_DISASSEMBLER_CLASS + " (" +
					disassemblerClass.getName() + "): " +
					language.getLanguageDescription().getLanguageID(), e);
			}
		}
		return new Disassembler(language, addrFactory, monitor, listener);
	}

	/**
	 * Get a suitable disassembler instance.
	 * @param program the program to be disassembled.
	 * @param markBadInstructions if true bad instructions will be marked
	 * @param markUnimplementedPcode if true instructions with unimplemented pcode will be marked
	 * @param restrictToExecuteMemory if true disassembly will only be permitted with executable memory blocks
	 * @param monitor progress monitor
	 * @param listener object to notify of disassembly messages.
	 * @return a disassembler ready to disassemble
	 */
	public static Disassembler getDisassembler(Program program, boolean markBadInstructions,
			boolean markUnimplementedPcode, boolean restrictToExecuteMemory, TaskMonitor monitor,
			DisassemblerMessageListener listener) {
		Class<? extends Disassembler> disassemblerClass =
			getLanguageSpecificDisassembler(program.getLanguage());
		if (disassemblerClass != null) {
			try {
				Constructor<? extends Disassembler> constructor =
					disassemblerClass.getConstructor(Program.class, boolean.class, boolean.class,
						boolean.class, TaskMonitor.class, DisassemblerMessageListener.class);
				return constructor.newInstance(program, markBadInstructions, markUnimplementedPcode,
					restrictToExecuteMemory, monitor, listener);
			}
			catch (Exception e) {
				throw new RuntimeException("Disassembler instantiation failure " +
					GhidraLanguagePropertyKeys.CUSTOM_DISASSEMBLER_CLASS + " (" +
					disassemblerClass.getName() + "): " +
					program.getLanguage().getLanguageDescription().getLanguageID(), e);
			}
		}
		return new Disassembler(program, markBadInstructions, markUnimplementedPcode,
			restrictToExecuteMemory, monitor, listener);
	}

	// TODO: Force use of factory methods above by making constructors protected

	/**
	 * Disassembler constructor.  Marking of bad instructions honors "Mark Bad Disassembly" 
	 * program Disassembler option.
	 * @param program the program to be disassembled.
	 * @param monitor progress monitor
	 * @param listener object to notify of disassembly messages.
	 */
	protected Disassembler(Program program, TaskMonitor monitor,
			DisassemblerMessageListener listener) {
		this(program, isMarkBadDisassemblyOptionEnabled(program),
			isMarkUnimplementedPcodeOptionEnabled(program), isRestrictToExecuteMemory(program),
			monitor, listener);
	}

	/**
	 * Disassembler constructor.  Intended for block pseudo-disassembly use only.
	 * @param language processor language
	 * @param addrFactory address factory 
	 * @param monitor progress monitor
	 * @param listener object to notify of disassembly messages.
	 */
	protected Disassembler(Language language, AddressFactory addrFactory, TaskMonitor monitor,
			DisassemblerMessageListener listener) {
		this(null, language, addrFactory, false, false, false, monitor, listener);
	}

	/**
	 * Disassembler constructor
	 * @param program the program to be disassembled.
	 * @param markBadInstructions if true bad instructions will be marked
	 * @param markUnimplementedPcode if true instructions with unimplemented pcode will be marked
	 * @param restrictToExecuteMemory if true disassembly will only be permitted with executable memory blocks
	 * @param monitor progress monitor
	 * @param listener object to notify of disassembly messages.
	 */
	protected Disassembler(Program program, boolean markBadInstructions,
			boolean markUnimplementedPcode, boolean restrictToExecuteMemory, TaskMonitor monitor,
			DisassemblerMessageListener listener) {
		this(program, program.getLanguage(), program.getAddressFactory(), markBadInstructions,
			markUnimplementedPcode, restrictToExecuteMemory, monitor, listener);
	}

	private Disassembler(Program program, Language language, AddressFactory addrFactory,
			boolean markBadInstructions, boolean markUnimplementedPcode,
			boolean restrictToExecuteMemory, TaskMonitor monitor,
			DisassemblerMessageListener listener) {

		this.program = program;
		this.language = language;
		this.addrFactory = addrFactory;
		this.parallelHelper = language.getParallelInstructionHelper();
		this.monitor = monitor;
		this.listener = listener;

		this.baseContextRegister = language.getContextBaseRegister();
		this.instAlignment = language.getInstructionAlignment();

		// TODO: Work towards making program optional (or its elements - like listing) 
		// so that this may be used like a pseudo-disassembler - e.g., for debugger)
		// Will also need to change PseudoInstruction, etc...

		if (program != null) {
			listing = program.getListing();
			realProgramContext = program.getProgramContext();
			bmMgr = program.getBookmarkManager();
		}
		else {
			defaultLanguageContext = new ProgramContextImpl(language);
			language.applyContextSettings(defaultLanguageContext);
		}

		doMarkBadInstructions = markBadInstructions;
		doMarkUnimplPcode = markUnimplementedPcode;
		//this.restrictToExecuteMemory = restrictToExecuteMemory;

		initializedAddressSet = getInitializedMemory(program, restrictToExecuteMemory);

		resetDisassemblerContext();
	}

	/**
	 * Set seed context which will be used to establish initial context at starting points
	 * which are not arrived at via a natural disassembly flow.  A null value will disable
	 * use of any previously set seed context
	 * @param seedContext initial context for disassembly
	 */
	public void setSeedContext(DisassemblerContextImpl seedContext) {
		if (seedContext != null && seedContext.getBaseContextRegister() != baseContextRegister) {
			throw new IllegalArgumentException(
				"Seed context register does not match disassembler's context register: " +
					baseContextRegister);
		}
		this.seedContext = seedContext;
	}

	/*
	 * Set the instruction threshold limit for a generated instruction set (default 2048).
	 * NOTE: Should not be modified while disassembler is in use - intended for testing only.
	 * @param limit
	 */
	void setInstructionSetSizeLimit(int limit) {
		instructionSetSizeLimit = limit;
	}

	/**
	 * Set the maximum number of instructions in a single run which contain the same byte values.
	 * Disassembly flow will stop and be flagged when this threshold is encountered.
	 * This check is set to MAX_REPEAT_PATTERN_LENGTH by default, and can be disabled by setting a value of -1
	 * NOTE: This restriction will only work for those cases where a given repeated byte 
	 * results in an instruction which has a fall-through.
	 * @param maxInstructions limit on the number of consecutive instructions with the same 
	 * byte values
	 */
	public void setRepeatPatternLimit(int maxInstructions) {
		repeatInstructionByteTracker.setRepeatPatternLimit(maxInstructions);
	}

	/**
	 * Set the region over which the repeat pattern limit will be ignored.
	 * This allows areas which have been explicitly disassembled to be 
	 * free of bad bookmarks caused by the repeat pattern limit being exceeded.
	 * @param set region over which the repeat pattern limit will be ignored
	 */
	public void setRepeatPatternLimitIgnored(AddressSetView set) {
		repeatInstructionByteTracker.setRepeatPatternLimitIgnored(set);
	}

	/**
	 * @param program the program to check
	 * @return true if program MARK_BAD_INSTRUCTION_PROPERTY has been enabled
	 */
	public static boolean isMarkBadDisassemblyOptionEnabled(Program program) {
		Options options = program.getOptions(Program.DISASSEMBLER_PROPERTIES);
		return options.getBoolean(MARK_BAD_INSTRUCTION_PROPERTY, true);
	}

	/**
	 * @param program the program to check
	 * @return true if program MARK_UNIMPL_PCODE_PROPERTY has been enabled
	 */
	public static boolean isMarkUnimplementedPcodeOptionEnabled(Program program) {
		Options options = program.getOptions(Program.DISASSEMBLER_PROPERTIES);
		return options.getBoolean(MARK_UNIMPL_PCODE_PROPERTY, true);
	}

	/**
	 * @param program the program to check
	 * @return true if program RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY has been enabled
	 */
	public static boolean isRestrictToExecuteMemory(Program program) {
		Options options = program.getOptions(Program.DISASSEMBLER_PROPERTIES);
		return options.getBoolean(RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY, false);
	}

	private static AddressSetView getInitializedMemory(Program program,
			boolean exectuableMemoryOnly) {
		if (program == null) {
			return null;
		}
		Memory memory = program.getMemory();

		// If EXTERNAL block is initialized - it needs to be removed from initialized set below
		MemoryBlock externalBlock = memory.getBlock(MemoryBlock.EXTERNAL_BLOCK_NAME);
		if (externalBlock != null && !externalBlock.isInitialized()) {
			externalBlock = null;
		}

		AddressSet set;
		if (!exectuableMemoryOnly) {
			if (externalBlock == null) {
				return memory.getLoadedAndInitializedAddressSet();
			}
			set = new AddressSet(memory.getLoadedAndInitializedAddressSet());
		}
		else {
			set = new AddressSet();
			for (MemoryBlock block : memory.getBlocks()) {
				if (block.isInitialized() && block.isExecute()) {
					set.add(block.getStart(), block.getEnd());
				}
			}
		}
		if (externalBlock != null) {
			set.delete(externalBlock.getStart(), externalBlock.getEnd());
		}
		return set;
	}

	/**
	 * Attempt disassembly of all undefined code units within the specified set of addresses.
	 * NOTE: A single instance of this Disassembler does not support concurrent
	 * invocations of the various disassemble methods.
	 * Disassembler must be instantiated with a Program object.
	 * @param startSet	the minimum set of addresses to disassemble
	 * @param restrictedSet the set of addresses that disassembling is restricted to (may be null)
	 * @param doFollowFlow	flag to follow references while disassembling.
	 * @return the set of addresses that were disassembled.
	 */
	public AddressSet disassemble(AddressSetView startSet, AddressSetView restrictedSet,
			boolean doFollowFlow) {
		return disassemble(startSet, restrictedSet, null, doFollowFlow);
	}

	/**
	 * Attempt disassembly of all undefined code units within the specified set of addresses.
	 * NOTE: A single instance of this Disassembler does not support concurrent
	 * invocations of the various disassemble methods.
	 * Disassembler must be instantiated with a Program object.
	 * @param startSet	the minimum set of addresses to disassemble
	 * @param restrictedSet the set of addresses that disassembling is restricted to (may be null)
	 * @param initialContextValue initial context value to be applied at the
	 * startAddr.  If not null this value will take precedence when combined with
	 * any seed value or program context.
	 * @param doFollowFlow	flag to follow references while disassembling.
	 * @return the set of addresses that were disassembled.
	 */
	public AddressSet disassemble(AddressSetView startSet, AddressSetView restrictedSet,
			RegisterValue initialContextValue, boolean doFollowFlow) {

		AddressSet disassembledAddrs;

		disassembledAddrs = new AddressSet();

		int alignment = language.getInstructionAlignment();

		AddressRangeIterator addressRanges = startSet.getAddressRanges();
		for (AddressRange addressRange : addressRanges) {
			if (monitor.isCancelled()) {
				break;
			}

			if (disassembledAddrs.contains(addressRange.getMinAddress(),
				addressRange.getMaxAddress())) {
				continue;
			}

			AddressSet todoSubset = new AddressSet(addressRange);

			while (!todoSubset.isEmpty() && !monitor.isCancelled()) {
				Address nextAddr = todoSubset.getMinAddress();

				// Check if location is already on disassembly list
				if (disassembledAddrs.contains(nextAddr)) {
					AddressRange doneRange = disassembledAddrs.getRangeContaining(nextAddr);
					todoSubset.delete(doneRange);
					continue;
				}

				todoSubset.delete(nextAddr, nextAddr);

				// must be aligned
				if (nextAddr.getOffset() % alignment != 0) {
					continue;
				}

				Data data = listing.getUndefinedDataAt(nextAddr);
				if (data == null) {
					AddressSetView undefinedRanges = null;
					try {
						undefinedRanges =
							program.getListing().getUndefinedRanges(todoSubset, true, monitor);
						todoSubset = new AddressSet(undefinedRanges);
					}
					catch (CancelledException e) {
						break;
					}
				}
				else {
					AddressSet currentSet =
						disassemble(nextAddr, restrictedSet, initialContextValue, doFollowFlow);

					if (!currentSet.isEmpty()) {  // nothing disassembled
						todoSubset.delete(currentSet);
						disassembledAddrs.add(currentSet);
					}
				}
				if (monitor.isCancelled()) {
					break;
				}
			}
		}
		return disassembledAddrs;
	}

	/**
	 * Disassembles code starting at startAddr and restricted to addrSet.
	 * NOTE: A single instance of this Disassembler does not support concurrent
	 * invocations of the various disassemble methods.
	 * Disassembler must be instantiated with a Program object.
	 * @param startAddr the address to begin disassembling.
	 * @param restrictedSet the set of addresses that disassembling is restricted to.
	 * @return AddressSet the set of addresses that were disassembled.
	 */
	public AddressSet disassemble(Address startAddr, AddressSetView restrictedSet) {
		return disassemble(startAddr, restrictedSet, true);
	}

	/**
	 * Disassembles code starting at startAddr and restricted to addrSet.
	 * NOTE: A single instance of this Disassembler does not support concurrent
	 * invocations of the various disassemble methods. 
	 * Disassembler must be instantiated with a Program object.
	 * @param startAddr the address to begin disassembling.
	 * @param restrictedSet the set of addresses that disassembling is restricted to.
	 * @param doFollowFlow flag to follow references while disassembling.
	 * @return AddressSet the set of addresses that were disassembled.
	 */
	public AddressSet disassemble(Address startAddr, AddressSetView restrictedSet,
			boolean doFollowFlow) {
		return disassemble(startAddr, restrictedSet, null, doFollowFlow);
	}

	/**
	 * Disassembles code starting at startAddr and restricted to addrSet.
	 * NOTE: A single instance of this Disassembler does not support concurrent
	 * invocations of the various disassemble methods.  
	 * Disassembler must be instantiated with a Program object.
	 * @param startAddr the address to begin disassembling.
	 * @param restrictedSet the set of addresses that disassembling is restricted to.
	 * @param initialContextValue initial context value to be applied at the
	 * startAddr.  If not null this value will take precedence when combined with
	 * any seed value or program context.
	 * @param doFollowFlow flag to follow references while disassembling.
	 * @return AddressSet the set of addresses that were disassembled.
	 */
	public AddressSet disassemble(Address startAddr, AddressSetView restrictedSet,
			RegisterValue initialContextValue, boolean doFollowFlow) {

		if (program == null) {
			throw new UnsupportedOperationException(
				"Method requires instantiation with a Program object");
		}

		this.followFlow = doFollowFlow;
		this.restrictedAddressSet = restrictedSet;

		if (initialContextValue != null &&
			initialContextValue.getRegister().getBaseRegister() != baseContextRegister) {
			throw new IllegalArgumentException("Invalid initialContextValue");
		}

		AddressSet disassembledAddrs = new AddressSet();
		AddressSet reallyDisassembledAddrs = new AddressSet();

		int addressableUnitSize = startAddr.getAddressSpace().getAddressableUnitSize();
		if ((instAlignment % addressableUnitSize) != 0 ||
			(startAddr.getOffset() % instAlignment) != 0) {
			reportMessage("Disassembly address " + startAddr + " violates " + instAlignment +
				"-byte instruction alignment");
			return reallyDisassembledAddrs;
		}

		disassemblerQueue = new DisassemblerQueue(startAddr, restrictedSet);

		DumbMemBufferImpl memBuffer = new DumbMemBufferImpl(program.getMemory(), startAddr);

		DisassemblerContextImpl seed = seedContext;
		if (seed != null) {
			RegisterValue seedValue = seed.getFlowContextValue(startAddr, false);
			if (seedValue != null) {
				disassemblerContext.setFutureRegisterValue(startAddr, seedValue);
			}
		}
		if (initialContextValue != null) {
			RegisterValue initialValue = disassemblerContext.getFlowContextValue(startAddr, false);
			if (initialValue != null) {
				initialValue = initialValue.combineValues(initialContextValue);
				disassemblerContext.setFutureRegisterValue(startAddr, initialValue);
			}
		}

		while (disassemblerQueue.continueProducingInstructionSets(monitor)) {

			try {
				InstructionBlock nextBlock =
					disassemblerQueue.getNextBlockToBeDisassembled(null, program.getMemory(), null);
				if (nextBlock == null) {
					break;
				}
				Address blockAddr = nextBlock.getStartAddress();
				CodeUnit cu = listing.getCodeUnitAt(blockAddr);
				if (cu instanceof Instruction) {
					continue; // skip call point silently if it was previously disassembled
				}
				if (!(cu instanceof Data) || ((Data) cu).isDefined()) {
					//Address flowAddr = flow.getDestinationAddress();
					if (cu == null) {
						// check for offcut conflict
						cu = listing.getCodeUnitContaining(blockAddr);
					}
					if (cu != null) {
						markCallConflict(blockAddr, blockAddr, cu);
						continue; // mark and skip call point if it conflicts with another code unit
					}
				}

				InstructionSet instructionSet =
					disassembleNextInstructionSet(nextBlock, memBuffer, disassembledAddrs);
				if (instructionSet == null) {
					continue;
				}

				// add instructions to program
				if (instructionSet.getInstructionCount() != 0) {
					AddressSetView newDisassembledAddrs =
						listing.addInstructions(instructionSet, false);
					if (newDisassembledAddrs != null) {
						if (doMarkUnimplPcode && !newDisassembledAddrs.isEmpty()) {
							markUnimplementedPcode(program, newDisassembledAddrs, monitor);
						}
						reallyDisassembledAddrs.add(newDisassembledAddrs);
					}
					disassembledAddrs.add(instructionSet.getAddressSet());
				}

				// Clear accumulated temporary program context which should
				// have been written to program
				disassemblerProgramContext.clearTemporaryContext();

				// check for disassembly errors and update disassembler queue
				disassembleCount +=
					disassemblerQueue.instructionSetAddedToProgram(instructionSet, this);

				if (disassembleCount >= NUM_ADDRS_FOR_NOTIFICATION) {
					totalCount += disassembleCount;
					monitor.setMessage("Disassembled  " + (totalCount / 1024) + " K");
					disassembleCount = 0;
				}
			}
			catch (CancelledException e) {
				break;
			}
			catch (CodeUnitInsertionException e) {
				Msg.error(this, e.getMessage());
			}
		}
		return reallyDisassembledAddrs;
	}

	private InstructionSet disassembleNextInstructionSet(InstructionBlock firstBlock,
			DumbMemBufferImpl programMemBuffer, AddressSetView previouslyDisassembled) {

		InstructionSet instructionSet = new InstructionSet(program.getAddressFactory());

		Address fallThruAddr = firstBlock.getStartAddress(); // allow us to enter loop with initial block

		InstructionBlock nextBlock;
		while ((nextBlock = disassemblerQueue.getNextBlockToBeDisassembled(fallThruAddr,
			programMemBuffer.getMemory(), monitor)) != null) {

			Address blockAddr = disassemblerQueue.getDisassemblyAddress();

			if (!disassemblerContext.isFlowActive()) {
				disassemblerContext.flowStart(blockAddr);
			}

			programMemBuffer.setPosition(blockAddr);
			disassembleInstructionBlock(nextBlock, programMemBuffer, nextBlock.getFlowFromAddress(),
				instructionSetSizeLimit - instructionSet.getInstructionCount(), instructionSet,
				true);
			if (monitor.isCancelled()) {
				break;
			}

			if (nextBlock.isEmpty()) {
				// no memory/bytes at specified blockAddr
				if (nextBlock.hasInstructionError()) {
					instructionSet.addBlock(nextBlock);
				}
				disassemblerContext.flowEnd(blockAddr);
				fallThruAddr = null;
			}
			else {
				instructionSet.addBlock(nextBlock);
				fallThruAddr = nextBlock.getFallThrough();
				if (fallThruAddr == null) {
					disassemblerContext.flowEnd(nextBlock.getMaxAddress());
				}
			}
			if (instructionSet.getInstructionCount() >= instructionSetSizeLimit) {
				// instruction set truncated
				break;
			}
		}
		if (disassemblerContext.isFlowActive()) {
			disassemblerContext.flowAbort();
		}
		return instructionSet;
	}

	/**
	 * Clear any retained context state which may have been accumulated.
	 * Use of this method is only needed when using the pseudoDisassembleBlock 
	 * method over an extended code range to avoid excessive in-memory state accumulation.
	 */
	public void resetDisassemblerContext() {
		disassemblerProgramContext = new DisassemblerProgramContext();
		disassemblerContext = new DisassemblerContextImpl(disassemblerProgramContext);
	}

	/**
	 * Perform a psuedo-disassembly of an single instruction block only following fall-throughs.
	 * WARNING! This method should not be used in conjunction with other disassembly methods
	 * on the this Disassembler instance.  Disassembler must be instantiated with a Program object.
	 * @param addr start of block
	 * @param defaultContextValue starting context to use if no context has previously been established
	 * for the specified startAddr
	 * @param limit maximum number of instructions to disassemble
	 * @return instruction block of pseudo-instructions
	 */
	public InstructionBlock pseudoDisassembleBlock(Address addr, RegisterValue defaultContextValue,
			int limit) {
		if (program == null) {
			throw new UnsupportedOperationException(
				"Method requires instantiation with a Program object");
		}
		return pseudoDisassembleBlock(new DumbMemBufferImpl(program.getMemory(), addr),
			defaultContextValue, limit);
	}

	/**
	 * Perform a psuedo-disassembly of an single instruction block only following fall-throughs.
	 * WARNING! This method should not be used in conjunction with other disassembly methods
	 * on the this Disassembler instance.
	 * @param blockMemBuffer block memory buffer 
	 * @param defaultContextValue starting context to use if no context has previously been established
	 * for the specified startAddr
	 * @param limit maximum number of instructions to disassemble
	 * @return instruction block of pseudo-instructions or null if minimum address of blockMemBuffer 
	 * is not properly aligned for instruction parsing.
	 */
	public InstructionBlock pseudoDisassembleBlock(MemBuffer blockMemBuffer,
			RegisterValue defaultContextValue, int limit) {

		Address startAddr = blockMemBuffer.getAddress();
		this.followFlow = false;

		int addressableUnitSize = startAddr.getAddressSpace().getAddressableUnitSize();
		if ((instAlignment % addressableUnitSize) != 0 ||
			(startAddr.getOffset() % instAlignment) != 0) {
			reportMessage("Disassembly address " + startAddr + " violates " + instAlignment +
				"-byte instruction alignment");
			return null;
		}

		DisassemblerContextImpl seed = seedContext;
		if (seed != null) {
			RegisterValue seedValue = seed.getFlowContextValue(startAddr, false);
			if (seedValue != null) {
				disassemblerContext.setFutureRegisterValue(startAddr, seedValue);
			}
		}

		if (baseContextRegister != null && defaultContextValue != null) {
			RegisterValue registerValue =
				disassemblerContext.getRegisterValue(baseContextRegister, startAddr);
			if (registerValue != null && !registerValue.hasAnyValue()) {
				registerValue = null;
			}
			RegisterValue defaultValue =
				disassemblerProgramContext.getDefaultValue(baseContextRegister, startAddr);
			if (defaultValue != null && !defaultValue.hasAnyValue()) {
				defaultValue = null;
			}
			if (SystemUtilities.isEqual(registerValue, defaultValue)) {
				// copy specified defaultContextValue to addr if context is language default
				// TODO: may need to use flowing context bits only for default
				disassemblerContext.setFutureRegisterValue(startAddr, defaultContextValue);
			}
		}

		disassemblerContext.flowStart(startAddr);

		InstructionBlock block = new InstructionBlock(startAddr);

		// preserve and disable bookmark settings
		boolean oldMarkBadInstructions = doMarkBadInstructions;
		boolean oldMarkUnimplementedPcode = doMarkUnimplPcode;
		doMarkBadInstructions = false;
		doMarkUnimplPcode = false;

		try {
			disassembleInstructionBlock(block, blockMemBuffer, null, limit, null, false);
		}
		catch (Exception e) {
			Msg.error(this, "Pseudo block disassembly failure at " + blockMemBuffer.getAddress() +
				": " + e.getMessage(), e);
		}
		finally {

			// restore bookmark settings
			doMarkBadInstructions = oldMarkBadInstructions;
			doMarkUnimplPcode = oldMarkUnimplementedPcode;

			if (block.isEmpty()) {
				disassemblerContext.flowAbort();
				return block;
			}

			if (baseContextRegister != null) {
				Address fallThruAddr = block.getFallThrough();
				if (fallThruAddr != null) {
					// Merge fall-through context into program context for in-memory retention
					disassemblerContext.copyToFutureFlowState(fallThruAddr);
				}
			}

			disassemblerContext.flowEnd(block.getMaxAddress());
		}
		return block;
	}

	/**
	 * Examine delay-slotted instruction to determine if it has a fall-through
	 * @param dsInstr pseudo-instruction within existingBlock
	 * @param existingBlock InstructionBlock containing dsInstr
	 * @return true if fallthrough exists
	 */
	private boolean delaySlottedInstructionHasFallthrough(Instruction dsInstr,
			InstructionBlock existingBlock) {
		while (dsInstr != null && dsInstr.isInDelaySlot()) {
			dsInstr = existingBlock.getInstructionAt(dsInstr.getMaxAddress().next());
		}
		return dsInstr != null; // instruction exists after delay slots
	}

	private void setMemoryConstraintError(InstructionBlock block, Address flowFrom) {
		Address startAddr = block.getStartAddress();
		MemoryBlock memBlock = program.getMemory().getBlock(startAddr);
		if (memBlock != null) {
			String reason;
			if (MemoryBlock.EXTERNAL_BLOCK_NAME.equals(memBlock.getName())) {
				// TODO: EXTERNAL block could be more formal other than by name
				return; // return empty block without error
			}
			else if (!memBlock.isLoaded()) {
				reason = "non-loaded";
			}
			else if (memBlock.isInitialized()) {
				// assume non-execute restriction was imposed
				reason = "non-execute";
			}
			else if (memBlock.isMapped()) {
				// Bit/Byte mapped blocks are considered uninitialized by memory manager
				reason = "mapped";
			}
			else {
				reason = "uninitialized";
			}
			String message = "Disassembly not permitted within " + reason + " memory block";
			block.setInstructionMemoryError(startAddr, flowFrom, message);
		}
		else {
			block.setInstructionMemoryError(startAddr, flowFrom,
				"Could not follow disassembly flow into non-existing memory at " + startAddr);
		}
	}

	protected void disassembleInstructionBlock(InstructionBlock block, MemBuffer blockMemBuffer,
			Address flowFrom, int limit, InstructionSet instructionSet,
			boolean skipIfBlockAlreadyDisassembled) {

		Address addr = blockMemBuffer.getAddress();
		repeatInstructionByteTracker.reset();

		if (initializedAddressSet != null && !initializedAddressSet.contains(addr)) {
			setMemoryConstraintError(block, flowFrom);
			return;
		}

		Instruction existingBlockStartInstr = null;
		if (skipIfBlockAlreadyDisassembled) {
			InstructionBlock existingBlock = instructionSet.getInstructionBlockContaining(addr);
			if (existingBlock != null && !existingBlock.isEmpty()) {
				existingBlockStartInstr = existingBlock.getInstructionAt(addr);
				if (existingBlockStartInstr == null) { // offcut condition
					existingBlockStartInstr =
						existingBlock.findFirstIntersectingInstruction(addr, addr);
					// TODO: no guarantee that the conflict code unit will actually get 
					// added to program - it may conflict itself with a program code unit
					block.setCodeUnitConflict(existingBlockStartInstr.getAddress(), addr, flowFrom,
						true, true);
					return;
				}
				else if (existingBlockStartInstr.isInDelaySlot() &&
					!delaySlottedInstructionHasFallthrough(existingBlockStartInstr,
						existingBlock)) {
					// Flow into existing delay slot - if delay-slotted instruction does not 
					// fall-through, we need to resume block after delay slots
					block = existingBlock;
					addr = existingBlock.getMaxAddress().next();
					existingBlockStartInstr = null;
				}
			}
		}

		try {
			while (!monitor.isCancelled() && addr != null) {

				if (restrictedAddressSet != null && !restrictedAddressSet.contains(addr)) {
					return; // no fall-through
				}

				disassemblerContext.flowToAddress(addr);

				MemBuffer instrMemBuffer =
					new WrappedMemBuffer(blockMemBuffer, DISASSEMBLE_MEMORY_CACHE_SIZE,
						(int) addr.subtract(blockMemBuffer.getAddress()));

				adjustPreParseContext(instrMemBuffer);

				RegisterValue contextValue = null;
				if (baseContextRegister != null) {
					contextValue = disassemblerContext.getRegisterValue(baseContextRegister);
				}

				InstructionPrototype prototype =
					language.parse(instrMemBuffer, disassemblerContext, false);

				// if fall-through already exists in another block - check for conflict 
				// and terminate terminate block
				if (!block.isEmpty() && instructionSet != null &&
					instructionSet.containsBlockAt(addr)) {
					existingBlockStartInstr = instructionSet.getInstructionAt(addr);
					if (existingBlockStartInstr != null) {
						InstructionPrototype existingProto = existingBlockStartInstr.getPrototype();
						if (!existingProto.equals(prototype)) {

							PseudoInstruction badInst = getPseudoInstruction(addr, prototype,
								instrMemBuffer, contextValue, block);
							InstructionError.dumpInstructionDifference(badInst,
								existingBlockStartInstr);

							block.setInconsistentPrototypeConflict(addr, flowFrom);
						}
						return;
					}
					// existing block must be an empty conflicted block - just keep going 
				}

				if (skipIfBlockAlreadyDisassembled && block.isEmpty()) {
					// start of block - skip block if already disassembled in the same way
					if (existingBlockStartInstr == null) {
						// check program if not previously found within instruction set
						existingBlockStartInstr = listing.getInstructionAt(addr);
					}
					if (existingBlockStartInstr != null) {
						InstructionPrototype existingProto = existingBlockStartInstr.getPrototype();
						if (existingProto.isInDelaySlot()) {
							// redo prototype parse for delay slot comparison
							prototype = language.parse(instrMemBuffer, disassemblerContext, true);
							if (existingProto.equals(prototype)) {
								// delay slots assumed to always fall-through - queue next addr
								disassemblerContext.copyToFutureFlowState(addr);
								if (disassemblerQueue != null) {
									disassemblerQueue
											.queueDelaySlotFallthrough(existingBlockStartInstr);
								}
								return;
							}
						}
						else if (existingProto.equals(prototype)) {
							// skip block start silently if it was previously disassembled
							return;
						}

						PseudoInstruction badInst = getPseudoInstruction(addr, prototype,
							instrMemBuffer, contextValue, block);
						InstructionError.dumpInstructionDifference(badInst,
							existingBlockStartInstr);

						block.setInconsistentPrototypeConflict(addr, flowFrom);
					}
				}

				PseudoInstruction inst =
					getPseudoInstruction(addr, prototype, instrMemBuffer, contextValue, block);

				Address maxAddr = inst.getMaxAddress();
				if (instructionSet != null && instructionSet.intersects(addr, maxAddr)) {
					InstructionBlock existingBlock =
						instructionSet.getInstructionBlockContaining(addr);
					Instruction existingInstr = null;
					if (existingBlock != null) {
						existingInstr = existingBlock.getInstructionAt(addr);
					}
					if (existingInstr == null) {
						if (existingBlock == null) {
							existingBlock =
								instructionSet.findFirstIntersectingBlock(addr, maxAddr);
						}
						existingInstr =
							existingBlock.findFirstIntersectingInstruction(addr, maxAddr);
						// TODO: no guarantee that the conflict code unit will actually get 
						// added to program - it may conflict itself with a program code unit
						block.setCodeUnitConflict(existingInstr.getAddress(), addr, flowFrom, true,
							true);
					}
					else {
						InstructionPrototype existingProto = existingInstr.getPrototype();
						if (existingInstr.isInDelaySlot()) {
							// redo prototype parse for delay slot comparison
							prototype = language.parse(instrMemBuffer, disassemblerContext, true);
						}

						if (!existingProto.equals(prototype)) {

							PseudoInstruction badInst = getPseudoInstruction(addr, prototype,
								instrMemBuffer, contextValue, block);
							InstructionError.dumpInstructionDifference(badInst,
								existingBlockStartInstr);

							block.setInconsistentPrototypeConflict(addr, flowFrom);
						}
					}
					return;
				}

				if (repeatInstructionByteTracker.exceedsRepeatBytePattern(inst)) {
					block.setParseConflict(addr, contextValue, flowFrom,
						"Maximum run of repeated byte instructions exceeded");
				}

				// process instruction flows and obtain fallthrough address
				addr = processInstruction(inst, blockMemBuffer, block, instructionSet);

				if (addr == null || block.hasInstructionError()) {
					return;
				}
				if (endBlockEarly(inst, addr, limit, block) || endBlockOnCall(inst, addr, block)) {
					// Preserve fallthrough context for future disassembly continuation.
					// No need to set block fallthrough, since special block flows
					// are added to facilitate future prioritization of flows
					// block.setFallThrough(addr);
					disassemblerContext.copyToFutureFlowState(addr);
					return;
				}

				flowFrom = inst.getMinAddress();
			}
		}
		catch (AddressOutOfBoundsException | AddressOverflowException e) {
			block.setInstructionMemoryError(addr, flowFrom,
				"Instruction does not fit within address space constraint");
		}
		catch (InsufficientBytesException e) {
			block.setInstructionMemoryError(addr, flowFrom, e.getMessage());
		}
		catch (UnknownInstructionException e) {
			block.setParseConflict(addr,
				disassemblerContext.getRegisterValue(disassemblerContext.getBaseContextRegister()),
				flowFrom, e.getMessage());
		}
	}

	private boolean endBlockEarly(Instruction inst, Address fallThruAddr, int limit,
			InstructionBlock block) {
		if (fallThruAddr == null) {
			return false;
		}
		if ((block.getInstructionCount() >= limit && isBlockTerminationOK(inst)) ||
			(initializedAddressSet != null && !initializedAddressSet.contains(fallThruAddr))) {
			// If instruction limit exceeded terminate block (provided we are not in the 
			// middle of a parallel packet), or falling into
			// uninitialized/non-execute memory, terminate block and
			// add fallthrough to branchStack.
			// Fallthrough must be handled immediately with next InstructionSet
			// to ensure that it remains the start of an InstructionBlock contained 
			// within an InstructionSet for the limit case
			disassemblerContext.copyToFutureFlowState(fallThruAddr);
			block.addBlockFlow(new InstructionBlockFlow(fallThruAddr, inst.getAddress(),
				InstructionBlockFlow.Type.PRIORITY));
			return true;
		}
		return false;
	}

	private boolean endBlockOnCall(Instruction inst, Address fallThruAddr, InstructionBlock block) {
		if (fallThruAddr == null || !inst.getFlowType().isCall() || !isBlockTerminationOK(inst)) {
			return false;
		}

		// Defer fallthrough processing for calls just in case it 
		// really does not return - process branches around it first.
		// This is not done if the call flow occurs in the middle of a parallel packet (unexpected)
		// Add fallthrough to branchStack
		disassemblerContext.copyToFutureFlowState(fallThruAddr);
		InstructionBlockFlow fallThrough = new InstructionBlockFlow(fallThruAddr, inst.getAddress(),
			InstructionBlockFlow.Type.CALL_FALLTHROUGH);
		// TODO: do we need to defer this longer? i.e., outside current IntructionSet

		if (disassemblerQueue != null) {
			disassemblerQueue.queueCurrentFlow(fallThrough);
		}
		block.addBlockFlow(fallThrough);
		block.addBranchFlow(fallThruAddr); // treat fall-through like branch flow
		return true;
	}

	/**
	 * Adjust disassembler context prior to disassembly of a new instruction.
	 * @param instrMemBuffer buffer for bytes from memory
	 * @throws UnknownInstructionException if instruction is invalid
	 */
	protected void adjustPreParseContext(MemBuffer instrMemBuffer)
			throws UnknownInstructionException {
		// nothing to do - method provided for disassembler extensions
	}

	protected PseudoInstruction getPseudoInstruction(Address addr, InstructionPrototype prototype,
			MemBuffer memBuffer, RegisterValue contextValue, InstructionBlock block)
			throws AddressOverflowException {
		PseudoInstruction instr;
		if (program != null) {
			instr = new PseudoInstruction(program, addr, prototype, memBuffer,
				disassemblerProgramContext.getInstructionContext(contextValue, addr,
					prototype.getLength()));
		}
		else {
			instr = new PseudoInstruction(addrFactory, addr, prototype, memBuffer,
				disassemblerProgramContext.getInstructionContext(contextValue, addr,
					prototype.getLength()));
		}
		instr.setInstructionBlock(block);
		return instr;
	}

	protected boolean isBlockTerminationOK(Instruction instr) {
		return parallelHelper == null || parallelHelper.isEndOfParallelInstructionGroup(instr);
	}

	/**
	 * Process a new instruction which has just been parsed.  This method is responsible for
	 * adding the instruction to the current block as well as any delay-slotted instructions.
	 * This method may be overridden and the instruction re-parsed if necessary. 
	 * @param inst instruction to process
	 * @param blockMemBuffer buffer to get bytes
	 * @param block current block of instructions
	 * @param instructionSet address set of current instructions in block
	 * @return instruction fallthrough address or null if no fallthrough
	 * @throws InsufficientBytesException if a memory error occurs during instruction processing 
	 * @throws UnknownInstructionException if an error occurs during a modified re-parse of
	 * the instruction.
	 * @throws AddressOverflowException if address goes out of address space
	 * @throws NestedDelaySlotException if delay slot found in a delay slot
	 */
	protected Address processInstruction(PseudoInstruction inst, MemBuffer blockMemBuffer,
			InstructionBlock block, InstructionSet instructionSet)
			throws InsufficientBytesException, UnknownInstructionException,
			AddressOverflowException, NestedDelaySlotException {

		List<PseudoInstruction> delaySlotList = parseDelaySlots(inst, blockMemBuffer, block);

		if (followFlow) {
			processInstructionFlows(inst, block);
		}

		block.addInstruction(inst);

		if (delaySlotList != null) {
			for (PseudoInstruction dsInstr : delaySlotList) {
				block.addInstruction(dsInstr);
				dsInstr.setInstructionBlock(block);
			}
		}

		// NOTE: Don't rely on instruction for fallthrough since this will not work
		// on a pseudo instruction when an instruction has delay slots.
		// Block fallthrough not yet established.
		if (!inst.hasFallthrough()) {
			return null;
		}
		return block.getMaxAddress().next();
	}

	private void processInstructionFlows(PseudoInstruction inst, InstructionBlock block) {
		// Process language specified flows only - following refs may result in context conflicts
		Address[] flowAddrs = inst.getFlows();
		FlowType flowType = inst.getFlowType();
		Address instAddr = inst.getMinAddress();

		// if this is an indirect call through a known address, put the address on flows to be checked for no-return
		//
		if (flowAddrs.length == 0 && flowType.isCall()) {
			checkForIndirectCallFlow(inst, flowType);
		}

		//Reference refsFrom[] = inst.getReferencesFrom();
		for (Address flowAddr : flowAddrs) {

			//check to see if function does not return...
			if (flowAddrs.length == 1 && flowType.isCall() && isNoReturnCall(inst, flowAddr)) {
				// do the override magic
				inst.setFlowOverride(FlowOverride.CALL_RETURN);
				continue;
			}

			if (flowAddr.getOffset() % instAlignment != 0) {
				block.setInstructionError(InstructionErrorType.FLOW_ALIGNMENT, instAddr, null, null,
					"Flow destination address " + flowAddr + " from " + instAddr + " violates " +
						instAlignment + "-byte instruction alignment");
			}
			else {
				disassemblerContext.copyToFutureFlowState(flowAddr);
				if (flowType.isCall()) {
					// queuing of call flow is deferred until after block has been
					// added to program - block used to hold onto it for later
					block.addBlockFlow(new InstructionBlockFlow(flowAddr, instAddr,
						InstructionBlockFlow.Type.CALL));
				}
				else {
					InstructionBlockFlow branchFlow = new InstructionBlockFlow(flowAddr, instAddr,
						InstructionBlockFlow.Type.BRANCH);
					if (disassemblerQueue != null) {
						disassemblerQueue.queueCurrentFlow(branchFlow);
					}
					block.addBlockFlow(branchFlow);
					block.addBranchFlow(flowAddr);
				}
			}
		}
	}

	private void checkForIndirectCallFlow(PseudoInstruction inst, FlowType flowType) {
		if (!flowType.isComputed() || flowType.isConditional()) {
			return;
		}
		for (int opIndex = 0; opIndex < inst.getNumOperands(); opIndex++) {
			RefType operandRefType = inst.getOperandRefType(opIndex);
			if (operandRefType.isIndirect()) {
				Address addr = inst.getAddress(opIndex);
				if (addr != null) {
					Function refFunc = program.getFunctionManager().getReferencedFunction(addr);
					if (refFunc != null && refFunc.hasNoReturn()) {
						inst.setFlowOverride(FlowOverride.CALL_RETURN);
						break;
					}
				}
			}
		}
	}

	private List<PseudoInstruction> parseDelaySlots(Instruction inst, MemBuffer blockMemBuffer,
			InstructionBlock block) throws NestedDelaySlotException {

		int minDelaySlotBytes = inst.getPrototype().getDelaySlotByteCount();
		if (minDelaySlotBytes == 0) {
			return null; // no delay slots
		}

		if (inst.isInDelaySlot()) {
			throw new NestedDelaySlotException();
		}

		Address instAddr = inst.getMinAddress();
		Address addr = instAddr;
		int length = inst.getLength();

		List<PseudoInstruction> instrList = new ArrayList<>();
		try {
			while (minDelaySlotBytes > 0) {

				try {
					addr = addr.addNoWrap(length);
				}
				catch (AddressOverflowException e) {
					block.setInstructionMemoryError(addr, inst.getAddress(),
						"Failed to properly process delay slot at end of address space");
					break;
				}

				disassemblerContext.flowToAddress(addr);

				MemBuffer dsInstrMemBuffer = new WrappedMemBuffer(blockMemBuffer,
					(int) addr.subtract(blockMemBuffer.getAddress()));

				// create one instruction
				InstructionPrototype prototype =
					language.parse(dsInstrMemBuffer, disassemblerContext, true);
				RegisterValue contextValue = null;
				if (baseContextRegister != null) {
					contextValue = disassemblerContext.getRegisterValue(baseContextRegister);
				}

				PseudoInstruction dsInstr =
					getPseudoInstruction(addr, prototype, dsInstrMemBuffer, contextValue, block);

				if (repeatInstructionByteTracker.exceedsRepeatBytePattern(dsInstr)) {
					block.setParseConflict(addr, contextValue, instAddr,
						"Maximum run of repeated byte instructions exceeded");
				}

				instrList.add(dsInstr);

				length = dsInstr.getLength();
				minDelaySlotBytes -= length;
			}
			return instrList;
		}
		catch (NestedDelaySlotException e) {
			throw e; // avoid UnknownInstructionException catch below
		}
		catch (AddressOutOfBoundsException | AddressOverflowException e) {
			block.setInstructionMemoryError(addr, instAddr,
				"Instruction does not fit within address space constraint");
		}
		catch (InsufficientBytesException e) {
			block.setInstructionMemoryError(addr, instAddr, e.getMessage());
		}
		catch (UnknownInstructionException e) {
			block.setParseConflict(addr,
				disassemblerContext.getRegisterValue(disassemblerContext.getBaseContextRegister()),
				instAddr, e.getMessage());
		}
		return null; // error occurred
	}

	/**
	 * Check if the called function doesn't return
	 * 
	 * @return true if the call also falls through to this instruction
	 */
	private boolean isNoReturnCall(Instruction instr, Address target) {
		// if allready overriden, return
		// is this function a call fixup
		if (program == null) {
			return false; // can't tell without program
		}
		Function func = program.getFunctionManager().getFunctionAt(target);
		if (func == null) {
			return false;
		}
		if (func.hasNoReturn()) {
			return true;
		}
		String callFixupStr = func.getCallFixup();
		if (callFixupStr == null || callFixupStr.length() == 0) {
			return false;
		}
		PcodeInjectLibrary pcodeInjectLibrary = program.getCompilerSpec().getPcodeInjectLibrary();
		InjectPayload callFixup =
			pcodeInjectLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, callFixupStr);
		if (callFixup == null) {
			return false;
		}
		return !callFixup.isFallThru();
	}

	@Override
	public void markInstructionError(InstructionError conflict) {

		Address address = conflict.getInstructionAddress();
		if (conflict.getInstructionErrorType() == InstructionErrorType.PARSE) {
			// retain context-register value if possible to facilitate parse debug
			RegisterValue contextValue = conflict.getParseContextValue();
			if (contextValue != null) {
				try {
					program.getProgramContext().setRegisterValue(address, address, contextValue);
				}
				catch (ContextChangeException e) {
					// ignore - existing instruction likely blocked context modification
				}
			}
		}

		if (!doMarkBadInstructions ||
			conflict.getInstructionErrorType() == InstructionErrorType.DUPLICATE) {
			return;
		}

		Address flowFrom = conflict.getFlowFromAddress();
		String flowMsg = flowFrom != null ? (" (flow from " + flowFrom + ")") : "";
		Address markAddr = address;
		if (!isBookmarkAllowed(markAddr)) {
			if (flowFrom != null) {
				markAddr = flowFrom;
			}
			else {
				return;
			}
		}

		bmMgr.setBookmark(markAddr, BookmarkType.ERROR, ERROR_BOOKMARK_CATEGORY,
			conflict.getConflictMessage() + flowMsg);

	}

	private boolean isBookmarkAllowed(Address addr) {
		MemoryBlock memBlock = program.getMemory().getBlock(addr);
		if (memBlock != null) {
			return memBlock.isInitialized();
		}
		return false;
	}

	private void markCallConflict(Address address, Address flowFrom, CodeUnit conflictCodeUnit) {
		if (!doMarkBadInstructions) {
			return;
		}
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block != null && !block.isInitialized()) {
			return;
		}
		String flowMsg = flowFrom != null ? (" (flow from " + flowFrom + ")") : "";
		bmMgr.setBookmark(address, BookmarkType.ERROR, ERROR_BOOKMARK_CATEGORY,
			"Failed to disassemble at " + address + " due to conflicting " +
				((conflictCodeUnit instanceof Instruction) ? "instruction" : "data") + flowMsg);
	}

	private static void markUnimplementedPcode(Instruction instr) {
		BookmarkManager bmMgr = instr.getProgram().getBookmarkManager();
		bmMgr.setBookmark(instr.getAddress(), BookmarkType.WARNING, UNIMPL_BOOKMARK_CATEGORY,
			"Instruction pcode is unimplemented: " + instr.getMnemonicString());
	}

	/**
	 * Mark all instructions with unimplemented pcode over the specified address set
	 * @param program to mark unimplemented in
	 * @param addressSet restricted address set or null for entire program
	 * @param monitor allow canceling
	 * @throws CancelledException if monitor canceled
	 */
	public static void markUnimplementedPcode(Program program, AddressSetView addressSet,
			TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		InstructionIterator instructions = (addressSet == null) ? listing.getInstructions(true)
				: listing.getInstructions(addressSet, true);
		while (instructions.hasNext()) {
			Instruction instr = instructions.next();
			PcodeOp[] pcode = instr.getPcode();
			if (pcode != null && pcode.length == 1 &&
				pcode[0].getOpcode() == PcodeOp.UNIMPLEMENTED) {
				markUnimplementedPcode(instr);
			}
		}
	}

	/**
	 * Clear all bookmarks which indicate unimplemented pcode within the specified address set.
	 * @param program program to clear bookmarks
	 * @param addressSet restricted address set or null for entire program
	 * @param monitor allow canceling
	 * @throws CancelledException if monitor canceled
	 */
	public static void clearUnimplementedPcodeWarnings(Program program, AddressSetView addressSet,
			TaskMonitor monitor) throws CancelledException {
		BookmarkManager bmMgr = program.getBookmarkManager();
		if (addressSet == null) {
			bmMgr.removeBookmarks(BookmarkType.WARNING, UNIMPL_BOOKMARK_CATEGORY, monitor);
		}
		else {
			bmMgr.removeBookmarks(addressSet, BookmarkType.WARNING, UNIMPL_BOOKMARK_CATEGORY,
				monitor);
		}
	}

	/**
	 * Clear all bookmarks which indicate Bad Instruction within the specified address set.
	 * @param program program to clear bookmarks
	 * @param addressSet restricted address set or null for entire program
	 * @param monitor allow canceling
	 * @throws CancelledException if monitor canceled
	 */
	public static void clearBadInstructionErrors(Program program, AddressSetView addressSet,
			TaskMonitor monitor) throws CancelledException {
		BookmarkManager bmMgr = program.getBookmarkManager();
		if (addressSet == null) {
			bmMgr.removeBookmarks(BookmarkType.ERROR, ERROR_BOOKMARK_CATEGORY, monitor);
		}
		else {
			bmMgr.removeBookmarks(addressSet, BookmarkType.ERROR, ERROR_BOOKMARK_CATEGORY, monitor);
		}
	}

	private void reportMessage(final String msg) {
		if (listener != null) {
			listener.disassembleMessageReported(msg);
		}
	}

	/**
	 * <code>DisassemblerProgramContext</code> is used as a proxy program context due to the 
	 * delayed nature of laying down instructions and their associated context state.
	 * This is used to track context not yet committed for use by the DisassemblerContext 
	 * in place of the true program context. 
	 */
	protected class DisassemblerProgramContext extends AbstractProgramContext {

		private AddressRangeObjectMap<RegisterValue> temporaryContextMap =
			new AddressRangeObjectMap<>();

		// instructionContextCache is an immutable context which may be used by multiple 
		// instructions
		private InstructionContext instructionContextCache = null;

		DisassemblerProgramContext() {
			super(Disassembler.this.language);
			if (realProgramContext != null) {
				setDefaultDisassemblyContext(realProgramContext.getDefaultDisassemblyContext());
			}
		}

		/**
		 * Following the parse of a new instruction prototype, get a immutable processor context
		 * for minting a new instruction.  If value is not null, the temporary context is expanded 
		 * to include the context-register value.  The temporary context should be cleared after in-memory
		 * instructions (i.e., InstructionSet) have been written to the program.
		 * @param value to add to instruction context if different
		 * @param instrAddr address of instruction that should have context
		 * @param instrLength length of instruction to set context
		 * @return instruction context with possible added value
		 */
		ProcessorContext getInstructionContext(RegisterValue value, Address instrAddr,
				int instrLength) {

			if (value == null) {
				// If null, implies no context register and should always be null
				if (instructionContextCache == null) {
					instructionContextCache =
						new InstructionContext(Disassembler.this.language, null);
				}
				return instructionContextCache;
			}

			if (instructionContextCache == null ||
				!SystemUtilities.isEqual(value, instructionContextCache.getContextValue())) {
				instructionContextCache = new InstructionContext(Disassembler.this.language, value);
			}

			// NOTE: It is possible for bad context flow to a location already
			// disassembled within the same InstructionSet to alter the temporary context
			// and produce conflict errors at that address.  The specified flowFrom may not be the
			// source of the bad context when multiple flow sources to that address exist.
			// This issue could be resolved here by throwing an exception if the specified
			// value differs from the value already contained in the temporaryContextMap 
			// at the cost of an additional lookup:

//			RegisterValue oldValue = temporaryContextMap.getObject(instrAddr);
//			if (oldValue != null && !oldValue.equals(value)) {
//				throw new SomeException // catch and produce conflict error
//			}

			Address maxAddr = instrAddr.add(instrLength - 1);
			temporaryContextMap.setObject(instrAddr, maxAddr, value);

			return instructionContextCache;
		}

		void clearTemporaryContext() {
			temporaryContextMap.clearAll();
		}

		@Override
		public Register[] getRegistersWithValues() {
			throw new UnsupportedOperationException(); // not used during disassembly
		}

		@Override
		public BigInteger getValue(Register register, Address address, boolean signed) {
			throw new UnsupportedOperationException(); // not used during disassembly
		}

		@Override
		public RegisterValue getRegisterValue(Register register, Address address) {

			// register assumed to always be valid context register during disassembly

			RegisterValue value = temporaryContextMap.getObject(address);
			if (value == null) {
				if (realProgramContext != null) {
					value = realProgramContext.getRegisterValue(register, address);
				}
				else {
					value = defaultLanguageContext.getDefaultValue(register, address);
				}
			}
			return value;
		}

		@Override
		public void setRegisterValue(Address start, Address end, RegisterValue value) {
			throw new UnsupportedOperationException(); // not used during disassembly
		}

		@Override
		public RegisterValue getNonDefaultValue(Register register, Address address) {

			// register assumed to always be valid context register during disassembly

			RegisterValue value = temporaryContextMap.getObject(address);
			if (value == null && realProgramContext != null) {
				value = realProgramContext.getNonDefaultValue(register, address);
			}
			return value;
		}

		@Override
		public void setValue(Register register, Address start, Address end, BigInteger value)
				throws ContextChangeException {
			throw new UnsupportedOperationException(); // not used during disassembly
		}

		@Override
		public AddressRangeIterator getRegisterValueAddressRanges(Register register) {
			throw new UnsupportedOperationException(); // not used during disassembly
		}

		@Override
		public AddressRangeIterator getRegisterValueAddressRanges(Register register, Address start,
				Address end) {
			throw new UnsupportedOperationException(); // not used during disassembly
		}

		@Override
		public AddressRange getRegisterValueRangeContaining(Register register, Address addr) {

			// register assumed to always be valid context register during disassembly

			AddressRange tempValueRange = temporaryContextMap.getAddressRangeContaining(addr);
			if (realProgramContext == null) {
				return tempValueRange;
			}

			// context range stored within program - need to check if we have already disassembled 
			// within this range and changed context
			AddressRange realValueRange =
				realProgramContext.getRegisterValueRangeContaining(register, addr);

			// we don't really care about the min address of the range since this is not used
			if (tempValueRange.getMaxAddress().compareTo(realValueRange.getMaxAddress()) < 0) {
				return tempValueRange;
			}
			return realValueRange;
		}

		@Override
		public AddressRangeIterator getDefaultRegisterValueAddressRanges(Register register) {
			throw new UnsupportedOperationException(); // not used during disassembly
		}

		@Override
		public AddressRangeIterator getDefaultRegisterValueAddressRanges(Register register,
				Address start, Address end) {
			throw new UnsupportedOperationException(); // not used during disassembly
		}

		@Override
		public void setDefaultValue(RegisterValue registerValue, Address start, Address end) {
			throw new UnsupportedOperationException(); // not used during disassembly
		}

		@Override
		public void remove(Address start, Address end, Register register)
				throws ContextChangeException {
			throw new UnsupportedOperationException(); // not used during disassembly
		}

		@Override
		public boolean hasValueOverRange(Register reg, BigInteger value, AddressSetView addrSet) {
			throw new UnsupportedOperationException(); // not used during disassembly
		}

		@Override
		public RegisterValue getDefaultValue(Register register, Address address) {

			// register assumed to always be valid context register during disassembly

			if (realProgramContext != null) {
				return realProgramContext.getDefaultValue(register, address);
			}
			return defaultLanguageContext.getDefaultValue(register, address);
		}

		@Override
		public RegisterValue getDisassemblyContext(Address address) {
			RegisterValue value = temporaryContextMap.getObject(address);
			if (value == null) {
				if (realProgramContext != null) {
					value = realProgramContext.getDisassemblyContext(address);
				}
				else if (baseContextRegister != null) {
					value = defaultLanguageContext.getDefaultValue(baseContextRegister, address);
				}
			}
			return value;
		}
	}

	/**
	 * InstructionContext is an immutable context for use when minting pseudo instructions.
	 */
	private static class InstructionContext implements ProcessorContext {

		private RegisterValue contextValue;
		private Language langauge;

		InstructionContext(Language language, RegisterValue contextValue) {
			this.langauge = language;
			this.contextValue = contextValue;
		}

		RegisterValue getContextValue() {
			return contextValue;
		}

		@Override
		public Register getBaseContextRegister() {
			return contextValue != null ? contextValue.getRegister().getBaseRegister() : null;
		}

		@Override
		public List<Register> getRegisters() {
			return langauge.getRegisters();
		}

		@Override
		public Register getRegister(String name) {
			return langauge.getRegister(name);
		}

		@Override
		public BigInteger getValue(Register register, boolean signed) {
			if (contextValue != null && register.isProcessorContext()) {
				return contextValue.getRegisterValue(register).getUnsignedValue();
			}
			return null;
		}

		@Override
		public RegisterValue getRegisterValue(Register register) {
			if (contextValue != null && register.isProcessorContext()) {
				return contextValue.getRegisterValue(register);
			}
			return null;
		}

		@Override
		public boolean hasValue(Register register) {
			return getRegisterValue(register).hasValue();
		}

		@Override
		public void setValue(Register register, BigInteger value) throws ContextChangeException {
			throw new UnsupportedOperationException();
		}

		@Override
		public void setRegisterValue(RegisterValue value) throws ContextChangeException {
			throw new UnsupportedOperationException();
		}

		@Override
		public void clearRegister(Register register) throws ContextChangeException {
			throw new UnsupportedOperationException();
		}

	}

	@SuppressWarnings("unchecked")
	private static Class<? extends Disassembler> getLanguageSpecificDisassembler(Language parser) {
		String className = parser.getProperty(GhidraLanguagePropertyKeys.CUSTOM_DISASSEMBLER_CLASS);
		if (className == null) {
			return null;
		}
		try {
			Class<?> disassemblerClass = Class.forName(className);
			if (!Disassembler.class.isAssignableFrom(disassemblerClass)) {
				Msg.error(Disassembler.class,
					"Invalid Class specified for " +
						GhidraLanguagePropertyKeys.CUSTOM_DISASSEMBLER_CLASS + " (" +
						disassemblerClass.getName() + "): " +
						parser.getLanguageDescription().getLanguageID());
				return null;
			}
			return (Class<? extends Disassembler>) disassemblerClass;
		}
		catch (ClassNotFoundException e) {
			throw new RuntimeException("Invalid Class specified for " +
				GhidraLanguagePropertyKeys.CUSTOM_DISASSEMBLER_CLASS + " (" + className + "): " +
				parser.getLanguageDescription().getLanguageID(), e);
		}
	}

}
