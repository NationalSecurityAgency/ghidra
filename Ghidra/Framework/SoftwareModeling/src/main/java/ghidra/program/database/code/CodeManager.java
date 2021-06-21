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
package ghidra.program.database.code;

import java.io.IOException;
import java.util.*;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.*;
import ghidra.program.database.data.DataTypeManagerDB;
import ghidra.program.database.map.*;
import ghidra.program.database.properties.*;
import ghidra.program.database.symbol.SymbolManager;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.lang.InstructionError.InstructionErrorType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.*;
import ghidra.program.util.ChangeManager;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Class to manage database tables for data and instructions.
 *
 */
public class CodeManager implements ErrorHandler, ManagerDB {

	private DBHandle dbHandle;
	private AddressMap addrMap;
	private CommentsDBAdapter commentAdapter;
	private DataDBAdapter dataAdapter;
	private InstDBAdapter instAdapter;
	private CommentHistoryAdapter historyAdapter;

	private ProgramDB program;
	private PrototypeManager protoMgr;
	private DBObjectCache<CodeUnitDB> cache;
	private DataTypeManagerDB dataManager;
	private EquateTable equateTable;
	private SymbolManager symbolTable;
	private ProgramContext contextMgr;
	private ReferenceManager refManager;
	private PropertyMapManager propertyMapMgr;
	private VoidPropertyMapDB compositeMgr;
	private IntPropertyMapDB lengthMgr;

	private boolean contextLockingEnabled = false;
	private boolean creatingInstruction = false;
	private volatile boolean redisassemblyMode = false;

	Lock lock;

	final static int DATA_OP_INDEX = 0; // operand index for data, will always be zero
	private static final int MAX_SEGMENT_LIMIT = 2;

	/**
	 * Constructs a new CodeManager for a program.
	 * @param handle handle to database
	 * @param addrMap addressMap to convert between addresses and long values.
	 * @param openMode either READ_ONLY, UPDATE, or UPGRADE
	 * @param lock the program synchronization lock
	 * @param monitor the task monitor use while upgrading.
	 * @throws VersionException if the database is incompatible with the current
	 * schema
	 * @throws IOException if a database io error occurs
	 * @throws CancelledException if the user cancels the upgrade operation
	 */
	public CodeManager(DBHandle handle, AddressMap addrMap, int openMode, Lock lock,
			TaskMonitor monitor) throws VersionException, CancelledException, IOException {

		dbHandle = handle;
		this.addrMap = addrMap;
		this.lock = lock;
		initializeAdapters(openMode, monitor);

		cache = new DBObjectCache<>(1000);
		protoMgr = new PrototypeManager(handle, addrMap, openMode, monitor);
		compositeMgr =
			new VoidPropertyMapDB(dbHandle, openMode, this, null, addrMap, "Composites", monitor);
		lengthMgr =
			new IntPropertyMapDB(dbHandle, openMode, this, null, addrMap, "Lengths", monitor);

		checkOldFallThroughMaps(handle, openMode, monitor);
	}

	/**
	 * Check for old fall-through/fall-from property maps.
	 * These maps were never fully supported so we do not support the read-only mode,
	 * however we will support an upgrade of this data which is now stored as FALL_THROUGH References.
	 * @param handle
	 * @param openMode
	 * @param monitor
	 * @throws VersionException
	 * @throws CancelledException
	 * @throws IOException
	 */
	private void checkOldFallThroughMaps(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {

		if (openMode != DBConstants.UPDATE) {
			return;
		}
		LongPropertyMapDB oldFallThroughs =
			new LongPropertyMapDB(dbHandle, openMode, this, null, addrMap, "FallThroughs", monitor);
		LongPropertyMapDB oldFallFroms =
			new LongPropertyMapDB(dbHandle, openMode, this, null, addrMap, "FallFroms", monitor);
		if (oldFallThroughs.getSize() != 0 || oldFallFroms.getSize() != 0) {
			throw new VersionException(true);
		}
	}

	/**
	 * Convert old fall-through overrides into References.
	 * @param monitor
	 * @throws CancelledException
	 * @throws IOException
	 */
	private void upgradeOldFallThroughMaps(TaskMonitor monitor)
			throws CancelledException, IOException {
		try {

			ReferenceManager refMgr = program.getReferenceManager();

			LongPropertyMapDB oldFallFroms = new LongPropertyMapDB(dbHandle, DBConstants.UPGRADE,
				this, null, addrMap, "FallFroms", monitor);

			LongPropertyMapDB oldFallThroughs = new LongPropertyMapDB(dbHandle, DBConstants.UPGRADE,
				this, null, addrMap, "FallThroughs", monitor);

			int cnt = oldFallThroughs.getSize();
			if (cnt != 0) {

				monitor.setMessage("Upgrade Fallthrough Overrides...");
				monitor.initialize(cnt);
				cnt = 0;

				AddressIterator addrIter = oldFallThroughs.getPropertyIterator();
				while (addrIter.hasNext()) {
					monitor.checkCanceled();
					Address addr = addrIter.next();
					try {
						long offset = oldFallThroughs.getLong(addr);
						Address toAddr = addr.getNewAddress(offset);
						refMgr.addMemoryReference(addr, toAddr, RefType.FALL_THROUGH,
							SourceType.USER_DEFINED, Reference.MNEMONIC);
					}
					catch (NoValueException e) {
						// skip
					}
					monitor.setProgress(++cnt);
				}
			}
			oldFallThroughs.delete();
			oldFallFroms.delete();

		}
		catch (VersionException e) {
			// Unexpected
			throw new IOException(e.getMessage());
		}
	}

	private void initializeAdapters(int openMode, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		VersionException versionExc = null;
		try {
			instAdapter = InstDBAdapter.getAdapter(dbHandle, openMode, addrMap, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			dataAdapter = DataDBAdapter.getAdapter(dbHandle, openMode, addrMap, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			commentAdapter = CommentsDBAdapter.getAdapter(dbHandle, openMode, addrMap, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			historyAdapter = CommentHistoryAdapter.getAdapter(dbHandle, openMode, addrMap, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		if (versionExc != null) {
			throw versionExc;
		}
	}

	/**
	 * Set the program after all the managers have been created.
	 * @param program The program object that this manager belongs to.
	 */
	@Override
	public void setProgram(ProgramDB program) {
		this.program = program;
		equateTable = program.getEquateTable();
		symbolTable = (SymbolManager) program.getSymbolTable();
		contextMgr = program.getProgramContext();
		refManager = program.getReferenceManager();
		propertyMapMgr = program.getUsrPropertyManager();
		dataManager = program.getDataTypeManager();
		protoMgr.setProgram(program);
	}

	/**
	 * @see ghidra.program.database.ManagerDB#programReady(int, int, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (openMode == DBConstants.UPGRADE) {
			upgradeOldFallThroughMaps(monitor);
		}
	}

	public void activateContextLocking() {
		if (program.getProgramContext().getBaseContextRegister() != null) {
			contextLockingEnabled = true;
		}
	}

	/**
	 * @see db.util.ErrorHandler#dbError(java.io.IOException)
	 */
	@Override
	public void dbError(IOException e) {
		program.dbError(e);
	}

	private CodeUnit startInstructionRange(Address firstInstrStart) throws IOException {

		Instruction inst = null;
		RecordIterator recIt = instAdapter.getRecords(firstInstrStart, true);
		if (recIt.hasNext()) {
			DBRecord rec = recIt.next();
			inst = getInstructionDB(rec);
			recIt.previous();
		}
		if (recIt.hasPrevious()) {
			DBRecord rec = recIt.previous();
			Instruction prevInst = getInstructionDB(rec);
			if (prevInst.getMaxAddress().compareTo(firstInstrStart) >= 0) {
				return prevInst;
			}
		}

		Data data = null;
		recIt = dataAdapter.getRecords(firstInstrStart, true);
		if (recIt.hasNext()) {
			DBRecord rec = recIt.next();
			data = getDataDB(rec);
			recIt.previous();
		}
		if (recIt.hasPrevious()) {
			DBRecord rec = recIt.previous();
			Data prevData = getDataDB(rec);
			if (prevData.getMaxAddress().compareTo(firstInstrStart) >= 0) {
				return prevData;
			}
		}

		if (data == null) {
			return inst;
		}
		if (inst == null) {
			return data;
		}
		return inst.getMinAddress().compareTo(data.getMinAddress()) < 0 ? inst : data;
	}

	private void checkInstructionSet(InstructionSet instructionSet, HashSet<Address> skipDelaySlots)
			throws IOException, CancelledException {

		CodeUnit nextCu = null;
		Address nextAddrInRange = null;
		boolean findNextCodeUnit = true;

		for (InstructionBlock block : instructionSet) {

			Address errorAddr = null;
			InstructionError conflict = block.getInstructionConflict();
			if (conflict != null) {
				errorAddr = conflict.getInstructionAddress();
				if (errorAddr == null) {
					continue; // skip block if block error has no instruction address
				}
			}
			if (block.isEmpty()) {
				continue; // skip empty blocks
			}

			Address blockStart = block.getStartAddress();
			if (findNextCodeUnit || !blockStart.equals(nextAddrInRange)) {
				// new range identify first potential conflict
				nextCu = startInstructionRange(blockStart);
				findNextCodeUnit = false;
			}

			Address flowFrom = block.getFlowFromAddress();
			for (Instruction protoInstr : block) {
				Address startAddr = protoInstr.getMinAddress();

				if (nextCu != null) {
					int c = nextCu.getMinAddress().compareTo(startAddr);
					boolean isInstruction = (nextCu instanceof Instruction);
					if (c == 0 && isInstruction) {
						Instruction inst = (Instruction) nextCu;
						if (protoInstr.isInDelaySlot() != inst.isInDelaySlot() &&
							inst.getLength() == protoInstr.getLength()) {
							if (protoInstr.isInDelaySlot()) {
								// overwrite conflicting instruction in delay slot - ignore conflict and resume,
								// no need to remove context since this will happen when instruction is added
								clearCodeUnits(inst.getMinAddress(), inst.getMinAddress(), false,
									TaskMonitorAdapter.DUMMY_MONITOR);
							}
							else {
								// Likely caused by odd flow into delay slot - assume OK - skip prototype and resume
								skipDelaySlots.add(startAddr); // keep existing delay slot instruction
							}
							try {
								nextCu = startInstructionRange(inst.getMaxAddress().addNoWrap(1));
							}
							catch (AddressOverflowException e) {
								nextCu = null;
							}
							continue;
						}
						else if (!protoInstr.getPrototype().equals(inst.getPrototype())) {

							InstructionError.dumpInstructionDifference(protoInstr, inst);

							block.setInconsistentPrototypeConflict(startAddr, flowFrom);
						}
						else {
							// signal block overlap with existing code
							// TODO: may not want to use conflict mechanism so that original conflict
							// will be preserved
							block.setInstructionError(InstructionErrorType.DUPLICATE, startAddr,
								startAddr, flowFrom, null);
						}
						findNextCodeUnit = true;
						break; // skip remainder of block
					}

					// the following check works in conjunction with the startInstructionRange
					// which insures that nextCu maxAddress will always be >= protoInstr minAddress
					c = nextCu.getMinAddress().compareTo(protoInstr.getMaxAddress());
					if (c <= 0) {
						// if isInstruction this is an offcut conflict
						block.setCodeUnitConflict(nextCu.getMinAddress(), startAddr, flowFrom,
							isInstruction, isInstruction);
						findNextCodeUnit = true;
						break; // skip remainder of block
					}
				}
				if (errorAddr != null && errorAddr.compareTo(startAddr) <= 0) {
					break; // skip remainder of block if disassembler error address encountered
				}
				flowFrom = startAddr;
			}
			nextAddrInRange = block.getMaxAddress().next();
		}
	}

	/**
	 * Creates a complete set of instructions.
	 * A preliminary pass will be made checking for code unit conflicts which will be
	 * marked within the instructionSet causing dependent blocks to get pruned.
	 * @param instructionSet the set of instructions to be added.  All code unit conflicts
	 * will be marked within the instructionSet and associated blocks.
	 */
	public AddressSetView addInstructions(InstructionSet instructionSet, boolean overwrite) {
		AddressSet set = new AddressSet();
		lock.acquire();
		creatingInstruction = true;
		try {

			HashSet<Address> skipDelaySlots = new HashSet<>();

			if (overwrite) {
				// Clear memory which corresponds to all code blocks
				// no need to remove context since this will happen when instruction is added
				for (AddressRange range : instructionSet.getAddressSet()) {
					clearCodeUnits(range.getMinAddress(), range.getMaxAddress(), false,
						TaskMonitorAdapter.DUMMY_MONITOR);
				}
			}
			else {
				// Check for conflicts with existing instructions,
				// Clear locations where delay-slots will be replacing
				// non-delay slot.  The skipDelaySlots set will
				// be filled-in with any existing delay slot locations
				// which should not be overwritten
				checkInstructionSet(instructionSet, skipDelaySlots);
			}

			// Add instruction blocks to program listing
			for (InstructionBlock block : instructionSet) {

				InstructionError conflict = block.getInstructionConflict();
				Address errorAddr = null;
				CodeUnit conflictCodeUnit = null;
				if (conflict != null) {
					errorAddr = conflict.getInstructionAddress();
					if (errorAddr == null) {
						continue; // skip block if block error has no instruction address
					}
					if (conflict.getInstructionErrorType().isConflict) {
						conflictCodeUnit = getCodeUnitAt(conflict.getConflictAddress());
						if ((conflictCodeUnit instanceof Data) &&
							!((Data) conflictCodeUnit).isDefined()) {
							conflictCodeUnit = null; // undefined code unit
						}
					}
				}

				// Delay Slot Note: delay slot group is added in reverse order to ensure that pcode
				// can be generated for delay-slotted instruction immediately after it is created

				Instruction protoInstr;
				boolean deferDS;
				int count = 0;
				Instruction lastInstruction = null;
				Iterator<Instruction> instructionIterator = block.iterator();
				Stack<Instruction> delaySlotStack = null;
				while (delaySlotStack != null || instructionIterator.hasNext()) {

					if (delaySlotStack != null) {
						protoInstr = delaySlotStack.pop();
						deferDS = false;
						if (delaySlotStack.isEmpty()) {
							delaySlotStack = null;
						}
					}
					else {
						protoInstr = instructionIterator.next();
						deferDS = true;
					}

					InstructionPrototype prototype = protoInstr.getPrototype();
					Address startAddr = protoInstr.getMinAddress();
					Address endAddr = protoInstr.getMaxAddress();

					if (prototype.hasDelaySlots()) {
						// perform bounds check on entire delay slot instruction group
						try {
							endAddr = startAddr.addNoWrap(prototype.getFallThroughOffset(
								protoInstr.getInstructionContext())).previous();
						}
						catch (AddressOverflowException e) {
							break;
						}
					}

					if (conflictCodeUnit != null && (endAddr.compareTo(errorAddr) >= 0 &&
						startAddr.compareTo(conflictCodeUnit.getMaxAddress()) <= 0)) {
						if (errorAddr.compareTo(protoInstr.getMaxAddress()) > 0) {
							Address flowFromAddr =
								(lastInstruction != null) ? lastInstruction.getAddress()
										: block.getFlowFromAddress();
							block.setCodeUnitConflict(conflict.getConflictAddress(), startAddr,
								flowFromAddr, conflict.isInstructionConflict(), false);
						}
						break; // terminate block prior to adding conflicted code unit
					}

					// skip instruction if we are attempting to lay down a non-delay slot prototype
					// onto an existing delay slot instruction although we need to continue
					// processing subsequent instructions

					if (!skipDelaySlots.contains(startAddr)) {

						if (!program.getMemory().contains(startAddr, endAddr)) {
							block.setInstructionError(InstructionErrorType.MEMORY, startAddr,
								startAddr, null, "Not enough bytes available for instruction");
							break;
						}

						if (deferDS && prototype.hasDelaySlots()) {
							if (delaySlotStack != null) {
								throw new AssertException();
							}
							delaySlotStack = new Stack<>();
							delaySlotStack.push(protoInstr);
							int dsCount = protoInstr.getDelaySlotDepth();
							while (dsCount-- != 0 && instructionIterator.hasNext()) {
								Instruction dsProtoInstr = instructionIterator.next();
								if (!dsProtoInstr.isInDelaySlot()) {
									break; // throw new AssertException();
								}
								if (skipDelaySlots.contains(dsProtoInstr.getAddress())) {
									break;
								}
								delaySlotStack.push(dsProtoInstr);
							}
							continue; // process delaySlotStack
						}

						lastInstruction =
							addInstruction(startAddr, endAddr, prototype, protoInstr, protoInstr);

						++count;

						if (protoInstr.isFallThroughOverridden()) {
							// copy fall-through override
							lastInstruction.setFallThrough(protoInstr.getFallThrough());
						}

						FlowOverride flowOverride = protoInstr.getFlowOverride();
						if (flowOverride != FlowOverride.NONE) {
							lastInstruction.setFlowOverride(flowOverride);
						}
					}

					if (errorAddr != null && conflictCodeUnit == null &&
						errorAddr.compareTo(startAddr) <= 0) {
						break; // skip remainder of block if disassembler conflict address encountered
					}
				}
				block.setInstructionsAddedCount(count);

				// fire event
				if (lastInstruction != null) {
					Address maxAddr = lastInstruction.getMaxAddress();
					InstructionPrototype prototype = lastInstruction.getPrototype();
					if (prototype.hasDelaySlots()) {
						try {
							maxAddr = lastInstruction.getAddress().addNoWrap(
								prototype.getFallThroughOffset(
									lastInstruction.getInstructionContext())).previous();
						}
						catch (AddressOverflowException e) {
							// ignore
						}
					}
					set.addRange(block.getStartAddress(), maxAddr);
					program.setChanged(ChangeManager.DOCR_CODE_ADDED, block.getStartAddress(),
						maxAddr, null, null);
				}
			}

		}
		catch (IOException e) {
			program.dbError(e);
		}
		catch (CancelledException e) {
			throw new AssertException(); // unexpected - no monitor
		}
		finally {
			creatingInstruction = false;
			lock.release();
		}
		return set;
	}

	/**
	 * Creates an instruction at the specified address.
	 *
	 * @param address start address of instruction
	 * @param prototype  instruction definition object
	 * @param memBuf the MemBuffer to use to get the bytes from memory
	 * @param context object that has the state of all the registers.
	 *
	 * @exception CodeUnitInsertionException thrown if code unit
	 *                  overlaps with an existing code unit
	 */
	public Instruction createCodeUnit(Address address, InstructionPrototype prototype,
			MemBuffer memBuf, ProcessorContextView context) throws CodeUnitInsertionException {

		lock.acquire();
		creatingInstruction = true;
		try {
			Address endAddr = address.addNoWrap(prototype.getLength() - 1);

			checkValidAddressRange(address, endAddr);

			InstructionDB inst = addInstruction(address, endAddr, prototype, memBuf, context);

			// fire event
			program.setChanged(ChangeManager.DOCR_CODE_ADDED, address, endAddr, null, inst);

			return inst;
		}
		catch (AddressOverflowException e) {
			throw new CodeUnitInsertionException("Code unit would extend beyond Address space");
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			creatingInstruction = false;
			lock.release();
		}
		return null;
	}

	private InstructionDB addInstruction(Address address, Address endAddr,
			InstructionPrototype prototype, MemBuffer memBuf, ProcessorContextView context)
			throws IOException {

		int protoID = protoMgr.getID(prototype, memBuf, context);
		prototype = protoMgr.getPrototype(protoID);

		Register contextReg = contextMgr.getBaseContextRegister();
		if (contextReg != null) {
			try {
				RegisterValue contextValue = context.getRegisterValue(contextReg);
				Address start = address;
				if (SystemUtilities.isEqual(contextValue,
					contextMgr.getDefaultValue(contextReg, start))) {
					contextMgr.setValue(contextReg, start, endAddr, null);
				}
				else {
					// Do not save non-flowing context beyond
					RegisterValue ctx = contextValue;
					if (contextMgr.hasNonFlowingContext() && !start.equals(endAddr)) {
						contextMgr.setRegisterValue(start, start, ctx);
						ctx = contextMgr.getFlowValue(ctx);
						start = start.next();
					}
					contextMgr.setRegisterValue(start, endAddr, ctx);
				}
			}
			catch (ContextChangeException e) {
				throw new AssertException(e.getMessage()); // Unexpected
			}
		}

		// create new instruction record
		long addr = addrMap.getKey(address, true);
		byte flags = 0;
		if (redisassemblyMode) {
			Byte byteFlags = redisassmblyFlags.get(addr);
			flags = (byteFlags == null) ? 0 : byteFlags;
		}
		instAdapter.createInstruction(addr, protoID, flags);

		cache.delete(addrMap.getKeyRanges(address, endAddr, false));

		// create new InstructionDB object and add to the cache (conflicts assumed to have been removed)
		InstructionDB inst = new InstructionDB(this, cache, address, addr, prototype, flags);

		addReferencesForInstruction(inst);
//				if (unlockedContextSet != null) {
//					unlockedContextSet.addRange(address, inst.getMaxAddress());
//				}

		return inst;
	}

	RegisterValue getOriginalPrototypeContext(InstructionPrototype prototype,
			Register baseContextReg) throws NoValueException {
		return protoMgr.getOriginalPrototypeContext(prototype, baseContextReg);
	}

	CommentsDBAdapter getCommentAdapter() {
		return commentAdapter;
	}

	/**
	 * Removes the block of defined bytes from the listing. All necessary checks will
	 * be made by listing before this method is called, so just do the work.
	 * @param start the first address in the range.
	 * @param end the last address in the range.
	 * @param monitor the TaskMonitor that tracks progress and is used to tell
	 * if the user cancels the operation.
	 * @throws CancelledException if the user cancels the operation.
	 */
	@Override
	public void deleteAddressRange(Address start, Address end, TaskMonitor monitor)
			throws CancelledException {

		// Expand range to include any overlaping or delay-slotted instructions
		CodeUnit cu = getCodeUnitContaining(start);
		if (cu != null) {
			start = cu.getMinAddress();
		}
		start = adjustStartForDelaySlot(start);
		end = adjustEndForDelaySlot(end);

		deleteAddressRange(start, end, false, monitor);
	}

	/**
	 * Removes the block of defined code units from the listing. All necessary checks will
	 * be made by listing before this method is called, so just do the work.
	 * @param start the first address in the range.
	 * @param end the last address in the range.
	 * @param keepComments if true comment and comment history will be retained
	 * @param monitor the TaskMonitor that tracks progress and is used to tell
	 * if the user cancels the operation.
	 * @throws CancelledException if the user cancels the operation.
	 */
	private void deleteAddressRange(Address start, Address end, boolean keepComments,
			TaskMonitor monitor) throws CancelledException {
		lock.acquire();
		boolean success = false;
		try {
			compositeMgr.removeRange(start, end);
			monitor.checkCanceled();
			instAdapter.deleteRecords(start, end);
			monitor.checkCanceled();
			dataAdapter.deleteRecords(start, end);
			monitor.checkCanceled();
			lengthMgr.removeRange(start, end);
			monitor.checkCanceled();
			if (!keepComments) {
				commentAdapter.deleteRecords(start, end);
				monitor.checkCanceled();
				historyAdapter.deleteRecords(start, end);
				monitor.checkCanceled();
			}

			cache.delete(addrMap.getKeyRanges(start, end, false));
			success = true;
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			if (!success) {
				cache.invalidate();
			}
			lock.release();
		}
	}

	/**
	 * Move a block of code from one address to a new address.
	 * Updates all property managers, symbols, and references.
	 *
	 * @param fromAddr the first address in the range to be moved.
	 * @param toAddr the address to move to.
	 * @param length the number of addresses to move.
	 * @param monitor the TaskMonitor that tracks progress and is used to tell
	 * if the user cancels the operation.
	 * @throws CancelledException if the user cancels the operation.
	 */
	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		lock.acquire();
		try {
			Address start = fromAddr;
			Address newStart = toAddr;
			Address newEnd = newStart.add(length - 1);

			monitor.setMessage("Moving code...");

			try {
				moveDefinedCodeUnits(start, newStart, length, monitor);
				invalidateCache(true);
				addMovedInstructionReferences(newStart, newEnd, monitor);
				addMovedDataReferences(newStart, newEnd, monitor);
			}
			catch (IOException e) {
				program.dbError(e);
			}
			invalidateCache(true);
		}
		finally {
			lock.release();
		}
	}

//	private int getOffsetSize(Register[] regs) {
//		int size = 0;
//		for(int i=0;i<regs.length;i++) {
//			if (regs[i].getOffset()+regs[i].getSize() > size) {
//				size = regs[i].getOffset()+regs[i].getSize();
//			}
//		}
//		return size;
//	}

	/**
	 * Returns the code unit whose min address equals
	 * the specified address.
	 *
	 * @param address the min address of the code unit to return
	 *
	 * @return CodeUnit the code unit at the specified address,
	 *                  or null if a code unit does not exist
	 */
	public CodeUnit getCodeUnitAt(Address address) {
		long addr = addrMap.getKey(address, false);
		// FIXME Trying to get Data to display for External.
		if (address.isExternalAddress()) {
			Symbol externalSymbol = program.getSymbolTable().getPrimarySymbol(address);
			if (externalSymbol == null) {
				return getUndefinedDataDB(address, addr);
			}
			ExternalLocation externalLocation =
				program.getExternalManager().getExternalLocation(externalSymbol);
			DataType dataType = externalLocation.getDataType();
			if (dataType == null || dataType == DataType.DEFAULT) {
				// For now dummy back an undefined.
				return getUndefinedDataDB(address, addr);
			}
			// Dummy back a Data for the data type.
			DataDB dataDB = new DataDB(this, null, addr, address, addr, dataType);
			return dataDB;
		}
		return getCodeUnitAt(addr);
	}

	CodeUnit getCodeUnitAt(long addr) {
		if (addr == AddressMap.INVALID_ADDRESS_KEY) {
			return null;
		}
		lock.acquire();
		try {
			CodeUnitDB cu = cache.get(addr);
			if (cu != null) {
				return cu;
			}

			try {
				InstructionDB inst = getInstructionDB(addr);
				if (inst != null) {
					return inst;
				}

				DataDB data = getDataDB(addr);
				if (data != null) {
					return data;
				}
				return getUndefinedAt(addrMap.decodeAddress(addr), addr);
			}
			catch (IOException e) {
				program.dbError(e);
			}
			return null;

		}
		finally {
			lock.release();
		}
	}

	/**
	 * Returns the next code unit whose min address is greater
	 * than the specified address.
	 *
	 * @param addr the address to look after
	 *
	 * @return CodeUnit the code unit after the specified address,
	 *                  or null if a code unit does not exist
	 */
	public CodeUnit getCodeUnitAfter(Address addr) {
		lock.acquire();
		try {
			CodeUnit cu = getCodeUnitContaining(addr);
			if (cu != null) {
				addr = cu.getMaxAddress();
			}
			Memory mem = program.getMemory();
			AddressIterator it = mem.getAddresses(addr, true);
			if (mem.contains(addr)) {
				it.next();
			}
			if (it.hasNext()) {
				addr = it.next();
				return getCodeUnitAt(addr);
			}
		}
		finally {
			lock.release();
		}
		return null;
	}

	/**
	 * Returns an iterator over all user-defined properties.
	 *
	 * @return Iterator an iterator over all user-defined properties
	 */
	public Iterator<String> getUserDefinedProperties() {
		return propertyMapMgr.propertyManagers();
	}

	/**
	 * Removes the user-defined property with the
	 * specified property name.
	 *
	 * @param propertyName the name of the user-defined property to remove
	 */
	public void removeUserDefinedProperty(String propertyName) {
		propertyMapMgr.removePropertyMap(propertyName);
	}

	/**
	 * Returns the property map object that is associated
	 * with the specified property name.
	 *
	 * @param propertyName  the name of the property
	 *
	 * @return PropertyMap  the property map object associated to the property name
	 */
	public PropertyMap getPropertyMap(String propertyName) {
		return propertyMapMgr.getPropertyMap(propertyName);
	}

	private CodeUnit getDefinedBefore(Address address) throws IOException {
		DBRecord dataRec = dataAdapter.getRecordBefore(address);
		DBRecord instRec = instAdapter.getRecordBefore(address);

		if (dataRec == null && instRec == null) {
			return null;
		}
		if (dataRec == null) {
			return getInstructionDB(instRec);
		}
		if (instRec == null) {
			return getDataDB(dataRec);
		}
		Address dataAddr = addrMap.decodeAddress(dataRec.getKey());
		Address instAddr = addrMap.decodeAddress(instRec.getKey());
		if (dataAddr.compareTo(instAddr) > 0) {
			return getDataDB(dataRec);
		}
		return getInstructionDB(instRec);
	}

	/**
	 * Returns the next code unit whose min address is
	 * closest to and less than the specified address.
	 *
	 * @param address the address to look before
	 *
	 * @return CodeUnit the code unit before the specified address,
	 *                  or null if a code unit does not exist
	 */
	public CodeUnit getCodeUnitBefore(Address address) {
		lock.acquire();
		try {
			AddressIterator it = program.getMemory().getAddresses(address, false);
			Address addr = null;
			if (it.hasNext()) {
				addr = it.next();
				if (addr.equals(address)) {
					addr = it.hasNext() ? it.next() : null;
				}
			}
			if (addr == null) {
				return null;
			}
			CodeUnit cu = getDefinedBefore(address);
			if (cu != null && cu.contains(addr)) {
				return cu;
			}
			return getUndefinedDataDB(addr, addrMap.getKey(addr, false));
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}

		return null;
	}

	/**
	 * Returns the code unit whose min address is less than
	 * or equal to the specified address and whose max address
	 * is greater than or equal to the specified address.
	 * <pre>{@literal
	 * codeunit.minAddress() <= addr <= codeunit.maxAddress()
	 * }</pre>
	 *
	 * @param address the address for which to find the code containing it.
	 *
	 * @return CodeUnit the code unit containing the specified address,
	 *                  or null if a code unit does not exist
	 */
	public CodeUnit getCodeUnitContaining(Address address) {
		lock.acquire();
		try {
			CodeUnit cu = getCodeUnitAt(address);
			if (cu != null) {
				return cu;
			}
			try {
				DBRecord dataRec = dataAdapter.getRecordBefore(address);
				DBRecord instRec = instAdapter.getRecordBefore(address);

				CodeUnit cuFirst = null, cuSecond = null;

				if (instRec != null) {
					cuFirst = getInstructionDB(instRec);
				}
				if (dataRec != null) {
					cuSecond = getDataDB(dataRec);
				}
				// if dataRec is > instrRec, swap order of checking
				if (dataRec != null && instRec != null) {
					Address dataAddr = addrMap.decodeAddress(dataRec.getKey());
					Address instAddr = addrMap.decodeAddress(instRec.getKey());
					if (dataAddr.compareTo(instAddr) > 0) {
						CodeUnit tmp = cuFirst;
						cuFirst = cuSecond;
						cuSecond = tmp;
					}
				}
				if (cuFirst != null && cuFirst.contains(address)) {
					return cuFirst;
				}
				if (cuSecond != null && cuSecond.contains(address)) {
					return cuSecond;
				}

				if (program.getMemory().contains(address)) {
					return getUndefinedAt(address);
				}
				// FIXME Trying to get Data to display for External.
				if (address.isExternalAddress()) {
					long addr = addrMap.getKey(address, false);
					Symbol externalSymbol = program.getSymbolTable().getPrimarySymbol(address);
					if (externalSymbol == null) {
						return getUndefinedDataDB(address, addr);
					}
					ExternalLocation externalLocation =
						program.getExternalManager().getExternalLocation(externalSymbol);
					DataType dataType = externalLocation.getDataType();
					if (dataType == null || dataType == DataType.DEFAULT) {
						// For now dummy back an undefined.
						return getUndefinedDataDB(address, addr);
					}
					// Dummy back a Data for the data type.
					DataDB dataDB = new DataDB(this, null, addr, address, addr, dataType);
					return dataDB;
				}
			}
			catch (IOException e) {
				dbError(e);
			}
			return null;

		}
		finally {
			lock.release();
		}
	}

	/**
	 * Get an iterator that contains the code units which have the specified
	 * property type defined. Only code units at an address greater than or
	 * equal to the specified start address will be returned by the iterator.
	 * If the start address is null then check the entire program.
	 * <br>
	 * Standard property types are defined in the CodeUnit class.
	 * The property types are:
	 *          <ul>
	 *              <li>COMMENT_PROPERTY</li>
	 *              <li>INSTRUCTION_PROPERTY</li>
	 *              <li>DEFINED_DATA_PROPERTY</li>
	 *          </ul>
	 * Property types can also be user defined.
	 *
	 * @param property the name of the user defined property type or special standard name from above.
	 * @param address the address to start the iterator, or null to iterator the entire program
	 * @param forward true means get iterator in the forward direction
	 *
	 * @return a CodeUnitIterator that returns all code units from the indicated
	 *         start address that have the specified property type defined.
	 */
	public CodeUnitIterator getCodeUnitIterator(String property, Address address, boolean forward) {
		if (program.getMemory().isEmpty()) {
			return new EmptyCodeUnitIterator();
		}

		if (address == null) {
			address = program.getMinAddress();
		}
		Address start = forward ? address : program.getMinAddress();
		Address end = forward ? program.getMaxAddress() : address;

		if (property.equals(CodeUnit.COMMENT_PROPERTY)) {
			try {
				AddressKeyIterator iter = commentAdapter.getKeys(start, end, forward);
				return new CodeUnitKeyIterator(this, iter, forward);
			}
			catch (IOException e) {
				program.dbError(e);
			}
		}
		else if (property.equals(CodeUnit.INSTRUCTION_PROPERTY)) {
			try {
				AddressKeyIterator iter = instAdapter.getKeys(start, end, forward);
				return new CodeUnitKeyIterator(this, iter, forward);
			}
			catch (IOException e) {
				program.dbError(e);
			}
		}
		else if (property.equals(CodeUnit.DEFINED_DATA_PROPERTY)) {
			try {
				AddressKeyIterator iter = dataAdapter.getKeys(start, end, forward);
				return new CodeUnitKeyIterator(this, iter, forward);
			}
			catch (IOException e) {
				program.dbError(e);
			}
		}
		else {
			// Possibly a user-defined property.
			PropertyMapDB pm = (PropertyMapDB) propertyMapMgr.getPropertyMap(property);
			if (pm != null) {
				try {
					AddressKeyIterator iter = pm.getAddressKeyIterator(start, end, forward);
					return new CodeUnitKeyIterator(this, iter, forward);
				}
				catch (IOException e) {
					program.dbError(e);
				}
			}
		}
		return new EmptyCodeUnitIterator();
	}

	/**
	 * Get an iterator that contains the code units which have the specified
	 * property type defined. Only code units starting within the address set
	 * specified will be returned by the iterator.
	 * If the address set is null then check the entire program.
	 * <br>
	 * Standard property types are defined in the CodeUnit class.
	 * The property types are:
	 *          <ul>
	 *              <li>REFERENCE_PROPERTY</li>
	 *              <li>INSTRUCTION_PROPERTY</li>
	 *              <li>DEFINED_DATA_PROPERTY</li>
	 *          </ul>
	 * Property types can also be user defined.
	 *
	 * @param property the name of the property type, or this can be user defined.
	 * @param addrSetView the address set to iterate, or null to iterate over the entire program
	 * @param forward true means the iterator is in the forward direction
	 * @return a CodeUnitIterator that returns all code units from the indicated
	 *         address set that have the specified property type defined.
	 */
	public CodeUnitIterator getCodeUnitIterator(String property, AddressSetView addrSetView,
			boolean forward) {

		if (addrSetView == null) {
			addrSetView = program.getMemory();
		}

		if (property.equals(CodeUnit.COMMENT_PROPERTY)) {
			try {
				AddressKeyIterator iter = commentAdapter.getKeys(addrSetView, forward);
				return new CodeUnitKeyIterator(this, iter, forward);
			}
			catch (IOException e) {
				program.dbError(e);
			}
		}
		if (property.equals(CodeUnit.INSTRUCTION_PROPERTY)) {
			try {
				AddressKeyIterator iter = instAdapter.getKeys(addrSetView, forward);
				return new CodeUnitKeyIterator(this, iter, forward);
			}
			catch (IOException e) {
				program.dbError(e);
			}
		}
		if (property.equals(CodeUnit.DEFINED_DATA_PROPERTY)) {
			try {
				AddressKeyIterator iter = dataAdapter.getKeys(addrSetView, forward);
				return new CodeUnitKeyIterator(this, iter, forward);
			}
			catch (IOException e) {
				program.dbError(e);
			}
		}
		// Possibly a user-defined property.
		PropertyMapDB pm = (PropertyMapDB) propertyMapMgr.getPropertyMap(property);
		if (pm != null) {
			try {
				AddressKeyIterator iter = pm.getAddressKeyIterator(addrSetView, forward);
				return new CodeUnitKeyIterator(this, iter, forward);
			}
			catch (IOException e) {
				program.dbError(e);
			}
		}
		return new EmptyCodeUnitIterator();
	}

	/**
	 * Get a forward iterator over code units that have comments of the given type.
	 * @param commentType comment type defined in CodeUnit
	 * @param set address set
	 */
	public CodeUnitIterator getCommentCodeUnitIterator(int commentType, AddressSetView set) {
		CodeUnitIterator it = getCodeUnitIterator(CodeUnit.COMMENT_PROPERTY, set, true);
		return new CommentTypeFilterIterator(it, commentType);
	}

	/**
	 * Get a forward iterator over addresses that have comments of the given type.
	 * @param commentType comment type defined in CodeUnit
	 * @param set address set
	 */
	public AddressIterator getCommentAddressIterator(int commentType, AddressSetView set,
			boolean forward) {
		try {
			AddressKeyIterator keyIter = commentAdapter.getKeys(set, forward);
			AddressIterator addrIter =
				new AddressKeyAddressIterator(keyIter, forward, addrMap, program);
			return new CommentTypeFilterAddressIterator(program, addrIter, commentType);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return new EmptyAddressIterator();
	}

	/**
	 * Get an iterator over addresses that have comments of any type.
	 * @param addrSet address set containing the comment addresses to iterate over.
	 * @param forward true to iterate in the direction of increasing addresses.
	 */
	public AddressIterator getCommentAddressIterator(AddressSetView addrSet, boolean forward) {
		try {
			AddressKeyIterator keyIter = commentAdapter.getKeys(addrSet, forward);
			return new AddressKeyAddressIterator(keyIter, forward, addrMap, program);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return new EmptyAddressIterator();
	}

	/**
	 * Returns the instruction whose min address equals
	 * the specified address or null if the address is not the beginning address
	 * of some codeunit.
	 *
	 * @param address the min address of the instruction to return
	 *
	 * @return CodeUnit the instruction at the specified address,
	 *                  or null if a instruction does not exist starting at the
	 * 				    given address.
	 */
	public Instruction getInstructionAt(Address address) {
		return getInstructionAt(addrMap.getKey(address, false));
	}

	InstructionDB getInstructionAt(long addr) {
		if (addr == AddressMap.INVALID_ADDRESS_KEY) {
			return null;
		}
		lock.acquire();
		try {
			CodeUnitDB cu = cache.get(addr);
			if (cu == null) {
				return getInstructionDB(addr);
			}
			else if (cu instanceof InstructionDB) {
				return (InstructionDB) cu;
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	/**
	 * Returns the defined data whose min address equals
	 * the specified address.
	 *
	 * @param address the min address of the data defined to return
	 *
	 * @return CodeUnit the defined data at the specified address,
	 *                  or null if a defined data does not exist
	 */
	public Data getDefinedDataAt(Address address) {
		return getDefinedDataAt(addrMap.getKey(address, false));
	}

	Data getDefinedDataAt(long addr) {
		if (addr == AddressMap.INVALID_ADDRESS_KEY) {
			return null;
		}
		lock.acquire();
		try {
			CodeUnit cu = cache.get(addr);
			if (cu == null) {
				DBRecord rec = dataAdapter.getRecord(addr);
				return getDataDB(rec);
			}
			else if (cu instanceof Data) {
				if (((Data) cu).isDefined()) {
					return (DataDB) cu;
				}
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	/**
	 * Returns the next instruction whose min address is
	 * closest to and less than the specified address.
	 *
	 * @param addr the address to look before
	 *
	 * @return Instruction the instruction before the specified address,
	 *                  or null if a instruction does not exist
	 */
	public Instruction getInstructionBefore(Address addr) {
		lock.acquire();
		try {
			DBRecord rec = instAdapter.getRecordBefore(addr);
			return getInstructionDB(rec);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	/**
	 * Returns the next instruction whose min address is greater
	 * than the specified address.
	 *
	 * @param addr the address to look after
	 *
	 * @return Instruction the instruction after the specified address,
	 *                  or null if a instruction does not exist
	 */
	public Instruction getInstructionAfter(Address addr) {
		lock.acquire();
		try {
			DBRecord rec = instAdapter.getRecordAfter(addr);
			return getInstructionDB(rec);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	/**
	 * Returns the instruction whose min address is less than
	 * or equal to the specified address and whose max address
	 * is greater than or equal to the specified address.
	 * <pre>{@literal
	 * instruction.minAddress() <= addr <= instruction.maxAddress()
	 * }</pre>
	 *
	 * @param address the address to be contained
	 *
	 * @return Instruction the instruction containing the specified address,
	 *                  or null if a instruction does not exist
	 */
	public Instruction getInstructionContaining(Address address) {
		lock.acquire();
		try {
			Instruction instr = getInstructionAt(address);

			if (instr != null) {
				return instr;
			}

			instr = this.getInstructionBefore(address);

			if (instr != null && instr.contains(address)) {
				return instr;
			}
			return null;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Returns the data whose min address equals
	 * the specified address.
	 *
	 * @param address the min address of the data to return
	 *
	 * @return Data the data at the specified address,
	 *                  or null if data does not exist
	 */
	public Data getDataAt(Address address) {
		return getDataAt(address, addrMap.getKey(address, false));
	}

	Data getDataAt(Address address, long addr) {
		if (addr == AddressMap.INVALID_ADDRESS_KEY) {
			return getUndefinedDataDB(address, addr);
		}
		lock.acquire();
		try {
			DataDB data = getDataDB(addr);
			if (data != null) {
				return data;
			}
			return getUndefinedAt(address, addr);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	/**
	 * Returns the next data whose min address is
	 * closest to and less than the specified address.
	 *
	 * @param addr the address to look before
	 *
	 * @return Data the data before the specified address,
	 *                  or null if a data does not exist
	 */
	public Data getDataBefore(Address addr) {
		CodeUnitIterator it = getCodeUnits(addr, false);
		CodeUnit cu = it.next();
		if (cu != null && !cu.getMinAddress().equals(addr)) {
			if (cu instanceof Data) {
				return (Data) cu;
			}
		}
		while (it.hasNext()) {
			cu = it.next();
			if (cu instanceof Data) {
				return (Data) cu;
			}
		}
		return null;
	}

	/**
	 * Returns the next data whose min address is greater
	 * than the specified address.
	 *
	 * @param addr the address to look after
	 *
	 * @return Data the data after the specified address,
	 *                  or null if a data does not exist
	 */
	public Data getDataAfter(Address addr) {
		CodeUnitIterator it = getCodeUnits(addr, true);
		if (getCodeUnitAt(addr) != null) {
			it.next();
		}
		while (it.hasNext()) {
			CodeUnit cu = it.next();
			if (cu instanceof Data) {
				return (Data) cu;
			}
		}
		return null;
	}

//	private int getDataLength(Record rec) {
//		DataType dt = dataManager.getDataType(rec.getLongValue(DataDBAdapter.DATA_TYPE_ID_COL));
//		if (dt.getLength() < 0) {
//			try {
//				return lengthMgr.getInt(addrMap.decodeAddress(rec.getKey()));
//			} catch (NoValueException e) {
//			}
//		}
//		return dt.getLength();
//	}

	/**
	 * Returns the data whose min address is less than
	 * or equal to the specified address and whose max address
	 * is greater than or equal to the specified address.
	 * <pre>{@literal
	 * data.minAddress() <= addr <= data.maxAddress()
	 * }</pre>
	 *
	 * @param addr the address to be contained
	 *
	 * @return Data the data containing the specified address,
	 *                  or null if a data does not exist that starts at that
	 * 				    address.
	 */
	public Data getDataContaining(Address addr) {
		CodeUnit cu = getCodeUnitContaining(addr);
		if (cu instanceof Data) {
			return (Data) cu;
		}
		return null;
	}

	/**
	 * Returns the next defined data whose min address is greater
	 * than the specified address.
	 *
	 * @param addr the address to look after
	 *
	 * @return Data the defined data after the specified address,
	 *                  or null if a defined data does not exist
	 */
	public Data getDefinedDataAfter(Address addr) {
		lock.acquire();
		try {
			DBRecord rec = dataAdapter.getRecordAfter(addr);
			return getDataDB(rec);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;

	}

	/**
	 * Returns the next defined data whose min address is
	 * closest to and less than the specified address.
	 *
	 * @param addr the address to look before
	 *
	 * @return Data the defined data before the specified address,
	 *                  or null if a defined data does not exist
	 */
	public Data getDefinedDataBefore(Address addr) {
		lock.acquire();
		try {
			DBRecord rec = dataAdapter.getRecordBefore(addr);
			return getDataDB(rec);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	/**
	 * Returns the defined data whose min address is less than
	 * or equal to the specified address and whose max address
	 * is greater than or equal to the specified address.
	 * <pre>{@literal
	 * data.minAddress() <= addr <= data.maxAddress()
	 * }</pre>
	 *
	 * @param addr the address to be contained
	 *
	 * @return Data the defined data containing the specified address,
	 *                  or null if a defined data does not exist
	 */
	public Data getDefinedDataContaining(Address addr) {
		lock.acquire();
		try {
			Data data = getDefinedDataAt(addr);
			if (data != null) {
				return data;
			}
			data = getDefinedDataBefore(addr);

			if (data != null) {
				if (data.contains(addr)) {
					return data;
				}
			}
			return null;
		}
		finally {
			lock.release();
		}
	}

	public AddressSetView getUndefinedRanges(AddressSetView set, boolean initializedMemoryOnly,
			TaskMonitor monitor) throws CancelledException {
		lock.acquire();
		try {
			if (monitor == null) {
				monitor = TaskMonitorAdapter.DUMMY_MONITOR;
			}
			Memory mem = program.getMemory();
			AddressSet searchSet;
			if (set == null) {
				searchSet = new AddressSet(
					initializedMemoryOnly ? mem.getLoadedAndInitializedAddressSet() : mem);
			}
			else {
				searchSet = new AddressSet(set);
				searchSet = searchSet.intersect(
					initializedMemoryOnly ? mem.getLoadedAndInitializedAddressSet() : mem);
			}
			AddressSet resultSet = new AddressSet();

			for (AddressRange range : searchSet.getAddressRanges()) {

				monitor.checkCanceled();

				Address start = range.getMinAddress();
				Address rangeMax = range.getMaxAddress();

				if (start.getAddressSpace().getMinAddress().compareTo(start) < 0) {
					// Adjust start if offcut
					try {
						Instruction instr = getInstructionBefore(start);
						if (instr != null && instr.contains(start)) {
							start = instr.getMaxAddress().addNoWrap(1);
							if (start.compareTo(rangeMax) > 0) {
								continue; // next range
							}
						}
						else {
							Data data = getDefinedDataBefore(start);
							if (data != null && data.contains(start)) {
								start = data.getMaxAddress().addNoWrap(1);
								if (start.compareTo(rangeMax) > 0) {
									continue; // next range
								}
							}
						}
					}
					catch (AddressOverflowException e) {
						continue; // next range
					}
				}

				RecordIterator instIter = instAdapter.getRecords(start, rangeMax, true);
				RecordIterator dataIter = dataAdapter.getRecords(start, rangeMax, true);

				Address nextInstAddr = null;
				Address nextDataAddr = null;
				Address nextInstEndAddr = null;
				Address nextDataEndAddr = null;

				while (true) {

					if (nextInstAddr == null && instIter.hasNext()) {
						DBRecord nextInstRec = instIter.next();
						nextInstAddr = addrMap.decodeAddress(nextInstRec.getKey());
						nextInstEndAddr = nextInstAddr;
						int protoID = nextInstRec.getIntValue(InstDBAdapter.PROTO_ID_COL);
						InstructionPrototype proto = protoMgr.getPrototype(protoID);
						int len = proto != null ? proto.getLength()
								: nextInstAddr.getAddressSpace().getAddressableUnitSize();
						if (len > 1) {
							try {
								nextInstEndAddr = nextInstAddr.addNoWrap(len - 1);
							}
							catch (AddressOverflowException e) {
								nextInstEndAddr = rangeMax;
							}
						}
					}

					if (nextDataAddr == null && dataIter.hasNext()) {
						DBRecord nextDataRec = dataIter.next();
						nextDataAddr = addrMap.decodeAddress(nextDataRec.getKey());
						nextDataEndAddr = nextDataAddr;
						DataDB data = getDataDB(nextDataRec);
						int len = data.getLength();
						if (len > 1) {
							try {
								nextDataEndAddr = nextDataAddr.addNoWrap(len - 1);
							}
							catch (AddressOverflowException e) {
								nextDataEndAddr = rangeMax;
							}
						}
					}

					if (nextInstAddr == null && nextDataAddr == null) {
						if (start.compareTo(rangeMax) <= 0) {
							resultSet.addRange(start, rangeMax);
						}
						break; // next range
					}

					// Decide which code unit is next: instruction or data and consume it
					Address nextDefinedAddr = nextInstAddr;
					Address nextDefinedEndAddr = nextInstEndAddr;
					if (nextInstAddr == null) {
						nextDefinedAddr = nextDataAddr;
						nextDefinedEndAddr = nextDataEndAddr;
					}
					if (nextInstAddr != null && nextDataAddr != null &&
						nextInstAddr.compareTo(nextDataAddr) > 0) {
						nextDefinedAddr = nextDataAddr;
						nextDefinedEndAddr = nextDataEndAddr;
						nextDataAddr = null; // consumed
					}
					else if (nextDefinedAddr == nextInstAddr) {
						nextInstAddr = null; // consumed
					}
					else {
						nextDataAddr = null; // consumed;
					}

					//
					if (start.compareTo(nextDefinedAddr) < 0) {
						resultSet.addRange(start, nextDefinedAddr.subtract(1));
					}

					if (nextDefinedEndAddr.compareTo(rangeMax) >= 0) {
						break; // next range
					}
					start = nextDefinedEndAddr.add(1);
				}
			}
			return resultSet;
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return null; // will not happen
	}

	/**
	 * Returns the undefined data whose min address equals
	 * the specified address.
	 *
	 * @param address the min address of the undefined data to return
	 *
	 * @return Data the undefined data at the specified address,
	 *                  or null if undefined data does not exist
	 */
	public Data getUndefinedAt(Address address) {
		return getUndefinedAt(address, addrMap.getKey(address, false));
	}

	Data getUndefinedAt(Address address, long addr) {
		if (addr != AddressMap.INVALID_ADDRESS_KEY) {
			lock.acquire();
			try {
				Instruction inst = getInstructionContaining(address);
				if (inst != null) {
					return null;
				}

				Data data = getDefinedDataContaining(address);
				if (data != null) {
					return null;
				}

				if (program.getMemory().contains(address)) {
					return getUndefinedDataDB(address, addr);
				}
			}
			finally {
				lock.release();
			}
		}

		// FIXME Trying to get Data to display for External.
		if (address.isExternalAddress()) {
			Symbol externalSymbol = program.getSymbolTable().getPrimarySymbol(address);
			if (externalSymbol == null) {
				return getUndefinedDataDB(address, addr);
			}
			ExternalLocation externalLocation =
				program.getExternalManager().getExternalLocation(externalSymbol);
			DataType dataType = externalLocation.getDataType();
			if (dataType == null || dataType == DataType.DEFAULT) {
				// For now dummy back an undefined.
				return getUndefinedDataDB(address, addr);
			}
			// Dummy back a Data for the data type.
			DataDB dataDB = new DataDB(this, null, addr, address, addr, dataType);
			return dataDB;
		}
		return null;
	}

	/**
	 * Returns the next undefined data whose min address is greater
	 * than the specified address.
	 *
	 * @param addr the address to look after
	 *
	 * @return Data the undefined data after the specified address,
	 *                  or null if a undefined data does not exist
	 */
	public Data getFirstUndefinedDataAfter(Address addr, TaskMonitor monitor) {
		if (!addr.isMemoryAddress() || addr.equals(addr.getAddressSpace().getMaxAddress())) {
			return null;
		}
		Memory mem = program.getMemory();
		AddressSetView set =
			mem.intersectRange(addr.next(), addr.getAddressSpace().getMaxAddress());

		int i = 0;
		CodeUnitIterator it = getCodeUnits(set, true);
		while (it.hasNext()) {
			CodeUnit cu = it.next();
			if (cu instanceof Data && !((Data) cu).isDefined()) {
				return (Data) cu;
			}
			if (++i % 1000 == 0) {
				monitor.setMessage("Searching address " + cu.getMinAddress());
			}
		}
		return null;
	}

	/**
	 * Returns the next undefined data whose min address falls within the address set
	 * searching in the forward direction {@code (e.g., 0 -> 0xfff).}
	 *
	 * @param set the address set to look within.
	 * @param monitor the current monitor.
	 * @return Data the first undefined data within the address set, or null if there is none.
	 */
	public Data getFirstUndefinedData(AddressSetView set, TaskMonitor monitor) {
		Memory mem = program.getMemory();
		set = mem.intersect(set);

		int i = 0;
		CodeUnitIterator it = getCodeUnits(set, true);
		while (it.hasNext()) {
			CodeUnit cu = it.next();
			if (cu instanceof Data && !((Data) cu).isDefined()) {
				return (Data) cu;
			}
			if (++i % 1000 == 0) {
				monitor.setMessage("Searching address " + cu.getMinAddress());
			}
		}
		return null;
	}

	/**
	 * Returns the next undefined data whose min address is
	 * closest to and less than the specified address.
	 *
	 * @param addr the address to look before
	 *
	 * @return Data the undefined data before the specified address,
	 *                  or null if a undefined data does not exist
	 */
	public Data getFirstUndefinedDataBefore(Address addr, TaskMonitor monitor) {
		if (!addr.isMemoryAddress() || addr.getOffset() == 0) {
			return null;
		}
		Memory mem = program.getMemory();
		AddressSetView set =
			mem.intersectRange(addr.getAddressSpace().getMinAddress(), addr.previous());

		int i = 0;
		CodeUnitIterator it = getCodeUnits(set, false);
		while (it.hasNext()) {
			CodeUnit cu = it.next();
			if (cu instanceof Data && !((Data) cu).isDefined()) {
				return (Data) cu;
			}
			if (++i % 1000 == 0) {
				monitor.setMessage("Searching address " + cu.getMinAddress());
			}
		}
		return null;
	}

	private void checkValidAddressRange(Address startAddr, Address endAddr)
			throws CodeUnitInsertionException, IOException {

		if (!program.getMemory().contains(startAddr, endAddr)) {
			long length = endAddr.subtract(startAddr) + 1;
			throw new CodeUnitInsertionException(
				"Insufficent memory at address " + startAddr + " (length: " + length + " bytes)");
		}

		RecordIterator recIt = instAdapter.getRecords(startAddr, true);
		if (recIt.hasNext()) {
			DBRecord rec = recIt.next();
			Instruction inst = getInstructionDB(rec);
			if (inst.getMinAddress().compareTo(endAddr) <= 0) {
				throw new CodeUnitInsertionException("Conflicting instruction exists at address " +
					inst.getMinAddress() + " to " + inst.getMaxAddress());
			}
			recIt.previous();
		}
		if (recIt.hasPrevious()) {
			DBRecord rec = recIt.previous();
			Instruction inst = getInstructionDB(rec);
			if (inst.getMaxAddress().compareTo(startAddr) >= 0) {
				throw new CodeUnitInsertionException("Conflicting instruction exists at address " +
					inst.getMinAddress() + " to " + inst.getMaxAddress());
			}
		}

		recIt = dataAdapter.getRecords(startAddr, true);
		if (recIt.hasNext()) {
			DBRecord rec = recIt.next();
			Data data = getDataDB(rec);
			if (data.getMinAddress().compareTo(endAddr) <= 0) {
				throw new CodeUnitInsertionException("Conflicting data exists at address " +
					data.getMinAddress() + " to " + data.getMaxAddress());
			}
			recIt.previous();
		}
		if (recIt.hasPrevious()) {
			DBRecord rec = recIt.previous();
			Data data = getDataDB(rec);
			if (data.getMaxAddress().compareTo(startAddr) >= 0) {
				throw new CodeUnitInsertionException("Conflicting data exists at address " +
					data.getMinAddress() + " to " + data.getMaxAddress());
			}
		}
	}

	/**
	 * Creates a data at the specified address.
	 *
	 * @param addr
	 *            Starting address of code unit
	 * @param dataType
	 *            data prototype for the code unit
	 * @exception CodeUnitInsertionException
	 *                thrown if code unit overlaps with an existing code unit
	 */
	public Data createCodeUnit(Address addr, DataType dataType, int length)
			throws CodeUnitInsertionException {

		lock.acquire();

		DataDB data = null;
		try {

			if (dataType instanceof BitFieldDataType) {
				throw new CodeUnitInsertionException("Bitfields not supported for Data");
			}

			DataType originalDataType = dataType;
			if (dataType instanceof FactoryDataType) {
				MemBuffer memBuffer = new MemoryBufferImpl(program.getMemory(), addr);
				dataType = ((FactoryDataType) dataType).getDataType(memBuffer);
				length = -1; // ignore user-specified length for factory use
			}

			if (dataType == null) {
				throw new CodeUnitInsertionException("Failed to resolve data type");
			}

			dataType = dataType.clone(dataManager); // make sure sizes are correct

			boolean isFunctionDef = (dataType instanceof FunctionDefinition);
			if (dataType instanceof TypeDef) {
				isFunctionDef =
					(((TypeDef) dataType).getBaseDataType() instanceof FunctionDefinition);
			}
			if (isFunctionDef) {
				dataType = new PointerDataType(dataType, dataType.getDataTypeManager());
				length = dataType.getLength();
			}
			else if (dataType instanceof Dynamic) {
				if (length <= 0 || !((Dynamic) dataType).canSpecifyLength()) {
					MemoryBlock block = program.getMemory().getBlock(addr);
					if (block == null || !block.isInitialized()) {
						throw new CodeUnitInsertionException(originalDataType.getName() +
							" may only be applied on initialized memory (" + addr + ")");
					}
				}
				Dynamic dynamicDataType = (Dynamic) dataType;
				MemBuffer memBuffer = new MemoryBufferImpl(program.getMemory(), addr);
				length = dynamicDataType.getLength(memBuffer, length);
			}
			else {
				length = dataType.getLength();
			}

			if (length < 0) {
				throw new CodeUnitInsertionException(
					"Failed to resolve data length for " + originalDataType.getName());
			}
			if (length == 0) {
				throw new CodeUnitInsertionException(
					"Zero-length data not allowed " + originalDataType.getName());
			}

			Address endAddr = addr.addNoWrap(length - 1);

			checkValidAddressRange(addr, endAddr);

			if (dataType == DataType.DEFAULT) {
				return getUndefinedDataDB(addr, addrMap.getKey(addr, false));
			}

			DBRecord record = dataAdapter.createData(addr, dataManager.getResolvedID(dataType));

			DataType baseDt = dataType;
			if (baseDt instanceof TypeDef) {
				baseDt = ((TypeDef) baseDt).getBaseDataType();
			}
			if (dataType.getLength() < 1) {
				lengthMgr.add(addr, length);
			}
			cache.delete(addrMap.getKeyRanges(addr, endAddr, false));

			data = getDataDB(record);
			baseDt = data.getBaseDataType();

			if (dataType instanceof Composite || dataType instanceof Array ||
				dataType instanceof Dynamic) {
				compositeMgr.add(addr);
				program.setChanged(ChangeManager.DOCR_COMPOSITE_ADDED, addr, endAddr, null, null);
			}

			// fire event
			program.setChanged(ChangeManager.DOCR_CODE_ADDED, addr, endAddr, null, data);

			addDataReferences(data, new ArrayList<Address>());

		}
		catch (AddressOverflowException e) {
			throw new CodeUnitInsertionException("Code unit would extend beyond Address space");
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return data;
	}

	/**
	 * Update the data references on this data item.
	 * Get rid of any references first, then add in any new ones.
	 *
	 * @param data   the data object to be updated
	 */
	public void updateDataReferences(Data data) {
		lock.acquire();
		try {
			refManager.removeAllReferencesFrom(data.getMinAddress(), data.getMinAddress());
			addDataReferences(data, new ArrayList<Address>());
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Add in any references from pointer data types found in a data item.
	 * We don't create refs for 0 or all f's.
	 * @param data the data to add references for.
	 * @param longSegmentAddressList used internally to make sure that, for 64 bit addresses, we
	 * don't pollute the the addressMap segment table when creating arrays of pointers on arbitrary
	 * data.
	 */
	private void addDataReferences(Data data, List<Address> longSegmentAddressList) {
		Memory mem = program.getMemory();
		MemoryBlock block = mem.getBlock(data.getAddress());
		if (block == null || !block.isInitialized()) {
			return;
		}
		DataType dt = data.getBaseDataType();
		if (Address.class.equals(dt.getValueClass(null))) {
			Object obj = data.getValue();
			if (obj instanceof Address) {
				// creates a reference unless the value is 0 or all f's
				createReference(data, (Address) obj, longSegmentAddressList);
			}
			return;
		}

		if (!containsAddressComponents(dt)) {
			return;
		}

		int numComponents = data.getNumComponents();
		for (int i = 0; i < numComponents; i++) {
			Data dataElement = data.getComponent(i);
			addDataReferences(dataElement, longSegmentAddressList);
		}
	}

	private boolean containsAddressComponents(DataType dt) {
		// get base type associated with array and/or typedef
		while ((dt instanceof Array) || (dt instanceof TypeDef)) {
			if (dt instanceof TypeDef) {
				dt = ((TypeDef) dt).getBaseDataType();
			}
			if (dt instanceof Array) {
				dt = ((Array) dt).getDataType();
			}
		}
		if ((dt instanceof DynamicDataType) || Address.class.equals(dt.getValueClass(null))) {
			// Assume DynamicDataType could produce an Address component
			return true;
		}
		if (dt instanceof Structure) {
			Structure structDt = (Structure) dt;
			for (DataTypeComponent component : structDt.getDefinedComponents()) {
				if (containsAddressComponents(component.getDataType())) {
					return true;
				}
			}
		}
		return false;
	}

	private void createReference(Data data, Address toAddr, List<Address> longSegmentAddressList) {
		if (toAddr == null || !toAddr.isLoadedMemoryAddress()) {
			return;
		}

		long offset = toAddr.getOffset();
		if (offset == 0 || offset == toAddr.getAddressSpace().getMaxAddress().getOffset()) {
			return; // treat 0 and all f's as uninitialized pointer value
		}

		// for 64 bit programs, make sure we are creating pointers on random bytes which would
		// pollute our 32 bit segment map and make Ghidra run poorly.
		if (toAddr.getAddressSpace().getSize() > 32) {
			if (exceedsLimitOn64BitAddressSegments(longSegmentAddressList, toAddr)) {
				return; // don't add the reference - probably garbage
			}
		}

		addDataReference(data.getMinAddress(), toAddr, true);
	}

	private boolean exceedsLimitOn64BitAddressSegments(List<Address> longSegmentAddressList,
			Address toAddr) {
		long maskedOffset = toAddr.getOffset() & 0xffffffff00000000L;
		for (int i = 0; i < longSegmentAddressList.size(); i++) {
			Address address = longSegmentAddressList.get(i);
			long offset = address.getOffset();
			if ((offset & 0xffffffff00000000L) == maskedOffset) {
				return false;
			}
		}
		if (longSegmentAddressList.size() < MAX_SEGMENT_LIMIT) {
			longSegmentAddressList.add(toAddr);
			return false;
		}
		return true;
	}

	private boolean addDataReference(Address fromAddr, Address toAddr, boolean isPrimary) {
		Reference ref =
			refManager.addMemoryReference(fromAddr, toAddr, RefType.DATA, SourceType.DEFAULT, 0);
		if (!isPrimary) {
			refManager.setPrimary(ref, isPrimary);
		}
		return true;
	}

	/**
	 * Clears all comments in the given range (inclusive).
	 *
	 * @param start  the start address of the range to clear
	 * @param end    the end   address of the range to clear
	 */
	public void clearComments(Address start, Address end) {
		lock.acquire();
		try {
			try {
				addCommentHistoryRecords(start, end);
			}
			catch (IOException e) {
				program.dbError(e);
			}
			//		cache.invalidate(startAddr, endAddr);
			cache.invalidate();
			try {
				boolean commentRemoved = commentAdapter.deleteRecords(start, end);
				if (commentRemoved) {
					// fire event
					program.setChanged(ChangeManager.DOCR_CODE_REMOVED, start, end, null, null);
				}
			}
			catch (IOException e) {
				program.dbError(e);
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Clears the properties in the given range (inclusive).
	 *
	 * @param start  the start address of the range to clear
	 * @param end    the end   address of the range to clear
	 */
	public void clearProperties(Address start, Address end, TaskMonitor monitor)
			throws CancelledException {
		propertyMapMgr.removeAll(start, end, monitor);
	}

	private Address adjustStartForDelaySlot(Address addr) {
		CodeUnit cu = getCodeUnitContaining(addr);
		if (cu == null) {
			return addr;
		}
		if (cu instanceof Instruction) {
			Instruction instr = (Instruction) cu;
			if (instr.isInDelaySlot()) {
				try {
					Address previousAddr = instr.getMinAddress().subtractNoWrap(1);
					return adjustStartForDelaySlot(previousAddr);
				}
				catch (AddressOverflowException e) {
					// ignore
				}
			}
		}
		return cu.getMinAddress();
	}

	private Address adjustEndForDelaySlot(Address addr) {
		CodeUnit cu = getCodeUnitContaining(addr);
		if (cu == null) {
			return addr;
		}
		if (cu instanceof Instruction) {
			Instruction instr = (Instruction) cu;
			boolean followDelay = (instr.getPrototype().hasDelaySlots()) || instr.isInDelaySlot();

			while (followDelay) {
				cu = instr;
				try {
					Address nextAddr = instr.getMaxAddress().addNoWrap(1);
					CodeUnit nextCu = getCodeUnitContaining(nextAddr);
					if (!(nextCu instanceof Instruction)) {
						break;
					}
					instr = (Instruction) nextCu;
					followDelay = instr.isInDelaySlot();
				}
				catch (AddressOverflowException e) {
					break;
				}
			}
		}
		return cu.getMaxAddress();
	}

	/**
	 * Remove code units, symbols, equates, and references to
	 * code units in the given range (inclusive).  Comments
	 * and comment history will be retained.
	 * @param start  the start address of the range to clear
	 * @param end    the end   address of the range to clear
	 * @param clearContext if true all context-register values will be cleared over range
	 * @param monitor the TaskMonitor that tracks progress and is used to tell
	 * if the user cancels the operation.
	 */
	public void clearCodeUnits(Address start, Address end, boolean clearContext,
			TaskMonitor monitor) throws CancelledException {
		lock.acquire();
		try {
			// Expand range to include any overlaping or delay-slotted instructions
			CodeUnit cu = getCodeUnitContaining(start);
			if (cu != null) {
				start = cu.getMinAddress();
			}
			start = adjustStartForDelaySlot(start);
			end = adjustEndForDelaySlot(end);

			refManager.removeAllReferencesFrom(start, end);
//					program.getProgramContext().deleteAddressRange(start, end, monitor);
			equateTable.deleteAddressRange(start, end, monitor);
			dataManager.deleteAddressRange(start, end, monitor);
			deleteAddressRange(start, end, true, monitor); // this invalidates the cache

			if (clearContext && contextMgr.getBaseContextRegister() != null) {
				try {
					contextMgr.remove(start, end, contextMgr.getBaseContextRegister());
				}
				catch (ContextChangeException e) {
					throw new AssertException(e);
				}
			}

			program.setChanged(ChangeManager.DOCR_CODE_REMOVED, start, end, cu, null);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Clear all code units in the program.
	 */
	public void clearAll(boolean clearContext, TaskMonitor monitor) {
		Address minAddr = program.getMinAddress();
		Address maxAddr = program.getMaxAddress();
		try {
			clearCodeUnits(minAddr, maxAddr, clearContext, monitor);
		}
		catch (CancelledException e) {
			// nothing to do
		}
	}

	/**
	 * Returns the number of instructions in the program.
	 */
	public int getNumInstructions() {
		try {
			return instAdapter.getRecordCount();
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return 0;
	}

	/**
	 * Returns the number of defined data in the program.
	 */
	public int getNumDefinedData() {
		try {
			return dataAdapter.getRecordCount();
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return 0;
	}

	/**
	  * Returns a composite data iterator beginning at the specified
	  * start address.
	  *
	  * @param start the address to begin iterator
	  * @param forward true means get iterator in forward direction
	  *
	  * @return DataIterator the composite data iterator
	  */
	public DataIterator getCompositeData(Address start, boolean forward) {
		try {
			return new DataKeyIterator(this, addrMap,
				compositeMgr.getAddressKeyIterator(start, forward));
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	/**
	 * Returns a composite data iterator limited to the addresses
	 * in the specified address set.
	 *
	 * @param addrSet the address set to limit the iterator
	 * @param forward determines if the iterator will go from the lowest address to
	 * the highest or the other way around.
	 * @return DataIterator the composite data iterator
	 */
	public DataIterator getCompositeData(AddressSetView addrSet, boolean forward) {
		try {
			return new DataKeyIterator(this, addrMap,
				compositeMgr.getAddressKeyIterator(addrSet, forward));
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	/**
	 * Returns an iterator over all codeUnits in the program from the given
	 * start address to either the end address or the start address, depending if
	 * the iterator is forward or not.
	 * @param start the starting address for the iterator.
	 * @param forward if true the iterator returns all codeUnits from the given
	 * start address to the end of the program, otherwise it returns all codeUnits
	 * from the given start address to the start of the program.
	 */
	public CodeUnitIterator getCodeUnits(Address start, boolean forward) {

		Memory mem = program.getMemory();
		AddressSet bounds;
		if (forward) {
			Address max = mem.getMaxAddress();
			if (start.compareTo(max) > 0) {
				return new EmptyCodeUnitIterator();
			}
			bounds = program.getAddressFactory().getAddressSet(start, max);
		}
		else {
			Address min = mem.getMinAddress();
			if (start.compareTo(min) < 0) {
				return new EmptyCodeUnitIterator();
			}
			bounds = program.getAddressFactory().getAddressSet(min, start);
		}

		return new CodeUnitRecordIterator(this, getInstructions(start, forward),
			getDefinedData(start, forward), mem.intersect(bounds), forward);
	}

	/**
	 * Returns an iterator over all codeUnits in the given addressSet. The iterator
	 * will go from the lowest address to the largest or from the largest to the
	 * lowest depending on the forward parameter.
	 * @param forward determines if the iterator goes from lowest address to highest
	 * or the other way around.
	 */
	public CodeUnitIterator getCodeUnits(AddressSetView set, boolean forward) {
		return new CodeUnitRecordIterator(this, getInstructions(set, forward),
			getDefinedData(set, forward), set, forward);
	}

	/**
	 * Returns an iterator over all instructions in the program from the given
	 * start address to either the end address or the start address, depending if
	 * the iterator is forward or not.
	 * @param address the starting address for the iterator.
	 * @param forward if true the iterator returns all instructions from the given
	 * start address to the end of the program, otherwise it returns all instructions
	 * from the given start address to the start of the program.
	 */
	public InstructionIterator getInstructions(Address address, boolean forward) {
		try {
			RecordIterator recIt = instAdapter.getRecords(address, forward);
			return new InstructionRecordIterator(this, recIt, forward);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	/**
	 * Returns an iterator over all defined data in the program from the given
	 * start address to either the end address or the start address, depending if
	 * the iterator is forward or not.
	 * @param address the starting address for the iterator.
	 * @param forward if true the iterator returns all defined data from the given
	 * start address to the end of the program, otherwise it returns all defined data
	 * from the given start address to the start of the program.
	 */
	public DataIterator getDefinedData(Address address, boolean forward) {
		try {
			RecordIterator recIt = dataAdapter.getRecords(address, forward);
			return new DataRecordIterator(this, recIt, forward);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	/**
	 * Returns an iterator over all instructions in the given addressSet. The iterator
	 * will go from the lowest address to the largest or from the largest to the
	 * lowest depending on the forward parameter.
	 * @param forward determines if the iterator goes from lowest address to highest
	 * or the other way around.
	 */
	public InstructionIterator getInstructions(AddressSetView set, boolean forward) {
		try {
			RecordIterator recIt = instAdapter.getRecords(set, forward);
			return new InstructionRecordIterator(this, recIt, forward);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;

	}

	/**
	 * Returns an iterator over all data in the program from the given
	 * start address to either the end address or the start address, depending if
	 * the iterator is forward or not.
	 * @param start the starting address for the iterator.
	 * @param forward if true the iterator returns all data from the given
	 * start address to the end of the program, otherwise it returns all data
	 * from the given start address to the start of the program.
	 */
	public DataIterator getData(Address start, boolean forward) {
		return new DataFilteredCodeUnitIterator(getCodeUnits(start, forward));
	}

	/**
	 * Returns an iterator over all data in the given addressSet. The iterator
	 * will go from the lowest address to the largest or from the largest to the
	 * lowest depending on the forward parameter.
	 * @param forward determines if the iterator goes from lowest address to highest
	 * or the other way around.
	 */
	public DataIterator getData(AddressSetView addrSet, boolean forward) {
		return new DataFilteredCodeUnitIterator(getCodeUnits(addrSet, forward));
	}

	/**
	 * Returns an iterator over all defined data in the given addressSet. The iterator
	 * will go from the lowest address to the largest or from the largest to the
	 * lowest depending on the forward parameter.
	 * @param forward determines if the iterator goes from lowest address to highest
	 * or the other way around.
	 */
	public DataIterator getDefinedData(AddressSetView addrSet, boolean forward) {
		try {
			return new DataRecordIterator(this, dataAdapter.getRecords(addrSet, forward), forward);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	/**
	 * Check if any instruction intersects the specified address range
	 * @param start start of range
	 * @param end end of range
	 */
	public void checkContextWrite(Address start, Address end) throws ContextChangeException {
		lock.acquire();
		try {
			if (!start.getAddressSpace().equals(end.getAddressSpace())) {
				throw new IllegalArgumentException();
			}
			if (!contextLockingEnabled || creatingInstruction ||
				!program.getMemory().contains(start, end)) {
				return;
			}
			boolean fail = false;
			if (getInstructionContaining(start) != null) {
				fail = true;
			}
			else {
				AddressRange range = new AddressRangeImpl(start, end);
				Instruction inst = getInstructionAfter(start);
				if (inst != null) {
					Address addr = inst.getMinAddress();
					if (range.contains(addr)) {
						fail = true;
					}
				}
			}
			if (fail) {
				throw new ContextChangeException(
					"Context register change conflicts with one or more instructions");
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Checks if all the addresses from start to end have undefined data.
	 * @param start the first address in the range to check.
	 * @param end the last address in the range to check.
	 * @return true if all the addresses in the range have undefined data.
	 */
	public boolean isUndefined(Address start, Address end) {
		if (!start.getAddressSpace().equals(end.getAddressSpace())) {
			return false;
		}
		if (!program.getMemory().contains(start, end)) {
			return false;
		}
		if (getInstructionContaining(start) != null) {
			return false;
		}
		if (getDefinedDataContaining(start) != null) {
			return false;
		}
		AddressRange range = new AddressRangeImpl(start, end);
		Instruction inst = getInstructionAfter(start);
		if (inst != null) {
			Address addr = inst.getMinAddress();
			if (range.contains(addr)) {
				return false;
			}
		}
		Data data = getDefinedDataAfter(start);
		if (data != null) {
			Address addr = data.getMinAddress();
			if (range.contains(addr)) {
				return false;
			}
		}
		return true;

	}

	protected boolean isUndefined(Address address, long addr) {
		if (program.getMemory().contains(address)) {
			try {
				DBRecord rec = dataAdapter.getRecord(addr);
				if (rec == null) {
					rec = instAdapter.getRecord(addr);
				}
				if (rec != null) {
					return false;
				}
				CodeUnit cu = getDefinedBefore(address);
				if (cu == null) {
					return true;
				}
				return cu.getMaxAddress().compareTo(address) < 0;
			}
			catch (IOException e) {
				program.dbError(e);
			}
		}
		return false;
	}

	/**
	 * Removes any data objects that have dataTypes matching the given dataType ids.
	 * @param dataTypeIDs the list of ids of dataTypes that have been deleted.
	 * @param monitor TaskMonitor used to monitor progress and keeps track if the
	 * user cancels the operation.
	 */
	public void clearData(long[] dataTypeIDs, TaskMonitor monitor) throws CancelledException {
		lock.acquire();
		try {
			List<Address> addrs = new ArrayList<>();
			RecordIterator it = dataAdapter.getRecords();
			while (it.hasNext()) {
				monitor.checkCanceled();
				DBRecord rec = it.next();
				long id = rec.getLongValue(DataDBAdapter.DATA_TYPE_ID_COL);
				for (long dataTypeID : dataTypeIDs) {
					if (id == dataTypeID) {
						addrs.add(addrMap.decodeAddress(rec.getKey()));
						break;
					}
				}
			}
			for (int i = 0; i < addrs.size(); i++) {
				monitor.checkCanceled();
				Address addr = addrs.get(i);
				clearCodeUnits(addr, addr, false, monitor);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
	}

	////////////////////////////////////////////////////////////////
	/**
	 * Get the program.
	 */
	Program getProgram() {
		return program;
	}

	/**
	 * Get the Symbol table.
	 */
	SymbolTable getSymbolTable() {
		return symbolTable;
	}

	/**
	 * Get the listing.
	 */
	Listing getListing() {
		return program.getListing();
	}

	/**
	 * Get the user property manager that manages user-defined
	 * properties.
	 */
	PropertyMapManager getPropertyMapManager() {
		return propertyMapMgr;
	}

	/**
	 * Get the InstructionDB object from the cache; if it is not in
	 * the cache, create a new DB object and add it.
	 * @param rec record for the instruction
	 */
	InstructionDB getInstructionDB(DBRecord rec) {
		lock.acquire();
		try {
			if (rec != null) {
				InstructionDB inst = (InstructionDB) cache.get(rec);
				if (inst != null) {
					return inst;
				}
				long addr = rec.getKey();
				Address address = addrMap.decodeAddress(addr);
				int protoID = rec.getIntValue(InstDBAdapter.PROTO_ID_COL);
				byte flags = rec.getByteValue(InstDBAdapter.FLAGS_COL);
				InstructionPrototype proto = protoMgr.getPrototype(protoID);
				inst = new InstructionDB(this, cache, address, addr, proto, flags);
				return inst;
			}
			return null;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Get the DataDB object from the cache; if it is not in the cache,
	 * create a new DB object and add it.
	 * @param rec data record
	 */
	DataDB getDataDB(DBRecord rec) {
		lock.acquire();
		try {
			if (rec != null) {
				DataDB data = (DataDB) cache.get(rec);
				if (data != null) {
					return data;
				}
				long addr = rec.getKey();
				Address address = addrMap.decodeAddress(addr);
				long datatypeID = rec.getLongValue(DataDBAdapter.DATA_TYPE_ID_COL);
				DataType dt = dataManager.getDataType(datatypeID);
				data = new DataDB(this, cache, addr, address, addr, dt);
				return data;
			}
			return null;

		}
		finally {
			lock.release();
		}
	}

	/**
	 * Get the adapter for the Data table.
	 */
	DataDBAdapter getDataAdapter() {
		return dataAdapter;
	}

	/**
	 * Get the adapter for the Instruction table.
	 */
	InstDBAdapter getInstructionAdapter() {
		return instAdapter;
	}

	Address getDefinedAddressAfter(Address address) {
		DBRecord dataRec = null;
		DBRecord instRec = null;
		try {
			dataRec = dataAdapter.getRecordAfter(address);
			instRec = instAdapter.getRecordAfter(address);
		}
		catch (IOException e) {
			program.dbError(e);
			return null;
		}
		if (dataRec == null && instRec == null) {
			return null;
		}
		if (dataRec == null) {
			return addrMap.decodeAddress(instRec.getKey());
		}
		if (instRec == null) {
			return addrMap.decodeAddress(dataRec.getKey());
		}
		Address dataAddr = addrMap.decodeAddress(dataRec.getKey());
		Address instAddr = addrMap.decodeAddress(instRec.getKey());
		if (dataAddr.compareTo(instAddr) < 0) {
			return dataAddr;
		}
		return instAddr;
	}

	///////////////////////////////////////////////////////////////////

	/**
	 * Move all user properties from the given range to the
	 * the newStart location.
	 */

	/**
	 * Move the prototypes in the range to the new start location.
	 */
	private void moveDefinedCodeUnits(Address startAddr, Address newStartAddr, long length,
			TaskMonitor monitor) throws IOException, CancelledException {

		lock.acquire();
		try {
			Address endAddr = startAddr.add(length - 1);

			compositeMgr.moveRange(startAddr, endAddr, newStartAddr);
			monitor.checkCanceled();

			lengthMgr.moveRange(startAddr, endAddr, newStartAddr);
			monitor.checkCanceled();

			instAdapter.moveAddressRange(startAddr, newStartAddr, length, monitor);
			dataAdapter.moveAddressRange(startAddr, newStartAddr, length, monitor);
			commentAdapter.moveAddressRange(startAddr, newStartAddr, length, monitor);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * For each instruction in the range being moved, create the
	 * symbols and add the references.
	 */
	private void addMovedInstructionReferences(Address start, Address end, TaskMonitor monitor)
			throws IOException, CancelledException {

		RecordIterator iter = instAdapter.getRecords(start, end, true);
		while (iter.hasNext()) {
			monitor.checkCanceled();
			InstructionDB inst = getInstructionDB(iter.next());
			addReferencesForInstruction(inst);
		}
	}

	/**
	 * For each instruction in the range being moved, create the
	 * symbols and add the references.
	 */
	private void addMovedDataReferences(Address start, Address end, TaskMonitor monitor)
			throws IOException, CancelledException {

		RecordIterator iter = dataAdapter.getRecords(start, end, true);
		while (iter.hasNext()) {
			monitor.checkCanceled();
			DBRecord rec = iter.next();
			Data data = getDataDB(rec);
			addDataReferences(data, new ArrayList<Address>());
		}
	}

	/**
	 * Updates the default references for a new or updated instruction.
	 */
	private void addReferencesForInstruction(InstructionDB inst) {

		List<Reference> oldRefList = null;
		if (redisassemblyMode) {
			for (Reference ref : refManager.getReferencesFrom(inst.getMinAddress())) {
				if (ref.getSource() != SourceType.DEFAULT || !ref.isMemoryReference()) {
					continue;
				}
				if (oldRefList == null) {
					oldRefList = new ArrayList<>();
				}
				oldRefList.add(ref);
			}
		}

		InstructionPrototype prototype = inst.getPrototype();

		Address[] flowAddrs = prototype.getFlows(inst);
		int remainingAddrs = flowAddrs.length;

		int opCount = prototype.getNumOperands();
		for (int opIndex = 0; opIndex < opCount; opIndex++) {
			// don't go through the instruction, go to the prototype,
			//  we only want the addresses reported by the prototype,
			//  not any addresses that are added by the user.
			int refCnt = 0;

			Reference operandPrimaryRef = null;

			// First look through the pieces of the operand to find the addresses
			ArrayList<Object> opList = prototype.getOpRepresentationList(opIndex, inst);
			for (Object obj : opList) {
				if (obj instanceof Address) {
					Address refAddr = (Address) obj;
					++refCnt;
					RefType refType =
						getOperandMemoryReferenceType(inst, opIndex, flowAddrs, refAddr);
					if (refType != null) {
						operandPrimaryRef = addDefaultMemoryReferenceIfMissing(inst, opIndex,
							refAddr, refType, oldRefList, operandPrimaryRef);
						--remainingAddrs;
					}
				}
			}
			// If there are still more addresses on this operand, see if the whole operand has any
			if (refCnt == 0 && remainingAddrs > 0) {
				Address refAddr = prototype.getAddress(opIndex, inst);
				if (refAddr != null) {
					RefType refType =
						getOperandMemoryReferenceType(inst, opIndex, flowAddrs, refAddr);
					if (refType != null) {
						operandPrimaryRef = addDefaultMemoryReferenceIfMissing(inst, opIndex,
							refAddr, refType, oldRefList, operandPrimaryRef);
						--remainingAddrs;
					}
				}
			}

			if (operandPrimaryRef != null && !operandPrimaryRef.isPrimary()) {
				// ensure that we have a primary ref on the operand if one exists
				refManager.setPrimary(operandPrimaryRef, true);
			}
		}

		Reference mnemonicPrimaryRef = null;

		for (Address flowAddr : flowAddrs) {
			if (flowAddr != null && flowAddr.isMemoryAddress()) {
				FlowType flowType = RefTypeFactory.getDefaultFlowType(inst, flowAddr, false);
				if (flowType == null) {
					flowType = RefType.INVALID;
				}
				boolean isFallthrough =
					(flowType.isJump() && flowAddr.equals(inst.getMaxAddress().next()));
				if (!isFallthrough) {
					mnemonicPrimaryRef = addDefaultMemoryReferenceIfMissing(inst, Reference.MNEMONIC,
						flowAddr, flowType, oldRefList, mnemonicPrimaryRef);
				}
			}
		}

		if (mnemonicPrimaryRef != null && !mnemonicPrimaryRef.isPrimary()) {
			// ensure that we have a primary ref on the mnemonic if one exists
			refManager.setPrimary(mnemonicPrimaryRef, true);
		}

		if (oldRefList != null && !oldRefList.isEmpty()) {
			for (Reference ref : oldRefList) {
				refManager.delete(ref);
			}
		}
	}

	/**
	 * Remove the specified reference is from oldRefList if present, otherwise add to instruction as a DEFAULT.
	 * Return as preferred primary reference if it previously existed as a primary reference in oldRefList or
	 * the specified operandPrimaryRef was null.
	 * @param inst instruction to which references apply
	 * @param opIndex operand to which reference applies
	 * @param refAddr default reference to-address
	 * @param refType default reference type
	 * @param oldRefList list of old references which exist on instruction which have 
	 * yet to be accounted for (may be null).
	 * @param operandPrimaryRef current preferred primary reference for operand
	 * @return updated preferred primary address for operand (i.e., operandPrimaryRef)
	 */
	private Reference addDefaultMemoryReferenceIfMissing(Instruction inst,
			int opIndex, Address refAddr, RefType refType, List<Reference> oldRefList,
			Reference operandPrimaryRef) {

		Reference ref = removeOldReference(oldRefList, refAddr, opIndex, refType);
		if (ref == null) {
			ref = refManager.addMemoryReference(inst.getMinAddress(), refAddr, refType,
				SourceType.DEFAULT, opIndex);
			if (operandPrimaryRef == null) {
				operandPrimaryRef = ref;
			}
		}
		else if (ref.isPrimary()) {
			operandPrimaryRef = ref;
		}
		return operandPrimaryRef;
	}

	/**
	 * Remove matching DEFAULT memory reference from oldRefList
	 * @param oldRefList list of existing DEFAULT memory references (may be null)
	 * @param toAddr new reference desination address
	 * @param opIndex new reference operand
	 * @param refType new reference type
	 * @return existing reference if it already exists in oldRefList, else null
	 */
	private Reference removeOldReference(List<Reference> oldRefList, Address toAddr, int opIndex,
			RefType refType) {
		if (oldRefList == null) {
			return null;
		}
		Iterator<Reference> iterator = oldRefList.iterator();
		while (iterator.hasNext()) {
			Reference ref = iterator.next();
			if (opIndex == ref.getOperandIndex() && refType == ref.getReferenceType() &&
				toAddr.equals(ref.getToAddress())) {
				iterator.remove();
				return ref;
			}
		}
		return null;
	}

	/**
	 * Get operand reference type for a new default memory reference
	 * @param inst instruction
	 * @param opIndex operand index
	 * @param flowAddrs known set of flow destination addresses.  Any address utilized from this
	 * list to produce an operand reference will be set to null within this array.
	 * @param refAddr reference to address
	 * @return reference type or null if refAddr corresponds to defined register
	 */
	private RefType getOperandMemoryReferenceType(InstructionDB inst, int opIndex,
			Address[] flowAddrs, Address refAddr) {
		if (program.getRegister(refAddr) != null) {
			return null;
		}

		RefType refType = RefTypeFactory.getDefaultMemoryRefType(inst, opIndex, refAddr, true);
		if (refType.isFlow()) {
			for (int j = 0; j < flowAddrs.length; j++) {
				if (refAddr.equals(flowAddrs[j])) {
					flowAddrs[j] = null;
					return refType;
				}
			}
			if (refType != RefType.INDIRECTION) {
				refType = RefType.DATA;
			}
		}
		return refType;
	}

	/**
	 * Returns the reference manager being used by this code manager.
	 *
	 * @return ReferenceManager the reference manager being used by this code manager
	 */
	public ReferenceManager getReferenceMgr() {
		return refManager;
	}

	/**
	 * Method getAddressMap.
	 * @return AddressMap
	 */
	AddressMap getAddressMap() {
		return addrMap;
	}

	int getLength(Address addr) {
		try {
			return lengthMgr.getInt(addr);
		}
		catch (NoValueException e) {
			return -1;
		}
	}

	private InstructionDB getInstructionDB(long addr) throws IOException {
		DBRecord rec = instAdapter.getRecord(addr);
		return getInstructionDB(rec);
	}

	protected DBRecord getInstructionRecord(long addr) {
		try {
			return instAdapter.getRecord(addr);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	DataType getDataType(long addr) {
		try {
			return getDataType(dataAdapter.getRecord(addr));
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	DataType getDataType(DBRecord dataRecord) {
		if (dataRecord != null) {
			long datatypeID = dataRecord.getLongValue(DataDBAdapter.DATA_TYPE_ID_COL);
			DataType dt = dataManager.getDataType(datatypeID);
			return dt;
		}
		return null;
	}

	private DataDB getDataDB(long addr) throws IOException {
		return getDataDB(dataAdapter.getRecord(addr));
	}

	private DataDB getUndefinedDataDB(Address address, long addr) {
		if (addr == AddressMap.INVALID_ADDRESS_KEY) {
// TODO: for now we will assume that all keys within defined memory blocks are known.
// When a memory block is created, only its start address key is generated, if the
// block spans a 32-bit boundary, null may be returned for all addresses beyond that
// boundary.  A recent fix was added to the memory map to ensure ensure that we can
// handle blocks which are at least 32-bits in size by ensuring that the end address
// key is also generated.
			return null;
		}
		lock.acquire();
		try {
			CodeUnit cu = cache.get(addr);
			if (cu == null) {
				if (address instanceof SegmentedAddress) {
					address = normalize((SegmentedAddress) address, program.getMemory());
				}
				DataDB data =
					new DataDB(this, cache, addr, address, addr, DefaultDataType.dataType);
				return data;
			}
			else if (cu instanceof Data) {
				if (!((Data) cu).isDefined()) {
					return (DataDB) cu;
				}
			}
			return null;
		}
		finally {
			lock.release();
		}
	}

	private Address normalize(SegmentedAddress addr, Memory memory) {
		if (memory == null) {
			return addr;
		}
		MemoryBlock block = memory.getBlock(addr);
		if (block == null) {
			return addr;
		}
		SegmentedAddress start = (SegmentedAddress) block.getStart();
		return addr.normalize(start.getSegment());

	}

//	private class KeyAdapter implements DBKeyAdapter {
//		private InstDBAdapter instAdapter;
//		private DataDBAdapter dataAdapter;
//		private boolean atStart;
//
//		private KeyAdapter(InstDBAdapter adapter, boolean atStart) {
//			instAdapter = adapter;
//			this.atStart = atStart;
//		}
//		private KeyAdapter(DataDBAdapter adapter, boolean atStart) {
//			dataAdapter = adapter;
//			this.atStart = atStart;
//		}
//		public DBLongIterator getKeys(Address start, Address end)
//			throws IOException {
//			if (instAdapter != null) {
//				return instAdapter.getKeys(start, end, atStart);
//			}
//			else {
//				return dataAdapter.getKeys(start, end, atStart);
//			}
//		}
//	}
//	private class PMKeyAdapter implements DBKeyAdapter {
//		private PropertyMapDB map;
//		private boolean atStart;
//
//		private PMKeyAdapter(PropertyMapDB map, boolean atStart) {
//			this.map = map;
//			this.atStart = atStart;
//		}
//		public DBLongIterator getKeys(Address start, Address end)
//			throws IOException {
//			return map.getLongAddressIterator(start, end, atStart);
//		}
//	}
//
//	private class CuAddrIterator implements CodeUnitIterator {
//		private AddressIterator iter;
//
//		private CuAddrIterator(AddressIterator iter) {
//			this.iter = iter;
//		}
//		/**
//		 * @see ghidra.program.model.listing.CodeUnitIterator#hasNext()
//		 */
//		public boolean hasNext() {
//			return iter.hasNext();
//		}
//
//
//		/**
//		 * @see ghidra.program.model.listing.CodeUnitIterator#next()
//		 */
//		public CodeUnit next() {
//			if (iter.hasNext()) {
//				return getCodeUnitAt(iter.next());
//			}
//			return null;
//		}
//	}
	/**
	 * Invalidates all cached database objects
	 */
	@Override
	public void invalidateCache(boolean all) {
		lock.acquire();
		try {
			cache.invalidate();
			lengthMgr.invalidateCache();
			compositeMgr.invalidateCache();
			protoMgr.clearCache();
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Invalidates the cache for the codeUnits.
	 *
	 */
	public void invalidateCodeUnitCache() {
		cache.invalidate();
	}

	/**
	 * Notification that memory has changed, so clear the cache for the
	 * affected code units.
	 * @param addr start of change
	 * @param end end address of change
	 */
	public void memoryChanged(Address addr, Address end) {
		lock.acquire();
//    	CodeUnit cu = getCodeUnitContaining(addr);
//    	if (cu != null) {
//    		addr = cu.getMinAddress();
//    	}
		try {
//    		cache.invalidate(addrMap.getKey(addr), addrMap.getKey(end));
			cache.invalidate();
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Callback from ReferenceManager when a new fall-through reference is set.
	 * @param fromAddr fall-through from location
	 * @param newFallThroughRef new fallthrough reference or null if removed
	 */
	public void fallThroughChanged(Address fromAddr, Reference newFallThroughRef) {
		lock.acquire();
		try {
			InstructionDB instr = getInstructionAt(addrMap.getKey(fromAddr, false));
			// TODO: Should prevent this if instruction is null or isInDelaySlot
			if (instr != null) {
				instr.fallThroughChanged(newFallThroughRef);
			}
		}
		finally {
			lock.release();
		}
	}

	void setFlags(long addr, byte flags) {
		try {
			instAdapter.updateFlags(addr, flags);
		}
		catch (IOException e) {
			program.dbError(e);
		}
	}

	/**
	 * Get the comment for the given type at the specified address.
	 *
	 * @param commentType either EOL_COMMENT, PRE_COMMENT,
	 * POST_COMMENT, PLATE_COMMENT, or REPEATABLE_COMMENT
	 * @param address the address of the comment.
	 * @return the comment string of the appropriate type or null if no comment of
	 * that type exists for this codeunit
	 * @throws IllegalArgumentException if type is not one of the
	 * types of comments supported
	 */
	public String getComment(int commentType, Address address) {
		try {
			long addr = addrMap.getKey(address, false);
			DBRecord commentRec = getCommentAdapter().getRecord(addr);
			if (commentRec != null) {
				return commentRec.getString(commentType);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		return null;
	}

	/**
	 * Set the comment for the given comment type at the specified address.
	 *
	 * @param address the address of the comment.
	 * @param commentType either EOL_COMMENT, PRE_COMMENT,
	 * POST_COMMENT, PLATE_COMMENT, or REPEATABLE_COMMENT
	 * @param comment comment to set at the address
	 * @throws IllegalArgumentException if type is not one of the
	 * types of comments supported
	 */
	public void setComment(Address address, int commentType, String comment) {
		CodeUnit cu = getCodeUnitAt(address);
		if (cu != null) {
			cu.setComment(commentType, comment);
			return;
		}
		lock.acquire();
		try {
			long addr = addrMap.getKey(address, true);
			DBRecord commentRec = getCommentAdapter().getRecord(addr);
			if (commentRec == null) {
				if (comment == null) {
					return;
				}
				commentRec = getCommentAdapter().createRecord(addr, commentType, comment);
				sendNotification(address, commentType, null, comment);
				return;
			}

			String oldValue = commentRec.getString(commentType);
			commentRec.setString(commentType, comment);
			sendNotification(address, commentType, oldValue, comment);

			for (int i = 0; i < CommentsDBAdapter.COMMENT_COL_COUNT; i++) {
				if (commentRec.getString(i) != null) {
					getCommentAdapter().updateRecord(commentRec);
					return;
				}
			}
			getCommentAdapter().deleteRecord(commentRec.getKey());
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
	}

	void sendNotification(Address address, int commentType, String oldValue, String newValue) {
		int eventType;
		switch (commentType) {
			case CodeUnit.PLATE_COMMENT:
				eventType = ChangeManager.DOCR_PLATE_COMMENT_CHANGED;
				break;
			case CodeUnit.PRE_COMMENT:
				eventType = ChangeManager.DOCR_PRE_COMMENT_CHANGED;
				break;
			case CodeUnit.POST_COMMENT:
				eventType = ChangeManager.DOCR_POST_COMMENT_CHANGED;
				break;
			case CodeUnit.REPEATABLE_COMMENT:
				eventType = ChangeManager.DOCR_REPEATABLE_COMMENT_CHANGED;
				break;
			case CodeUnit.EOL_COMMENT:
			default:
				eventType = ChangeManager.DOCR_EOL_COMMENT_CHANGED;
		}
		createCommentHistoryRecord(address, commentType, oldValue, newValue);

		program.setChanged(eventType, address, address, oldValue, newValue);

	}

	void createCommentHistoryRecord(Address address, int commentType, String oldComment,
			String newComment) {
		if (oldComment == null) {
			oldComment = "";
		}
		if (newComment == null) {
			newComment = "";
		}

		StringDiff[] diffs = StringDiffUtils.getLineDiffs(newComment, oldComment);

		long date = System.currentTimeMillis();
		long addr = addrMap.getKey(address, true);
		try {
			for (StringDiff diff : diffs) {
				historyAdapter.createRecord(addr, (byte) commentType, diff.start, diff.end,
					diff.text, date);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
	}

	/**
	 * Get the comment history for the comment type at the given address 
	 * 
	 * @param addr address for the comment history
	 * @param commentType comment type
	 * @return zero length array if no history exists
	 */
	public CommentHistory[] getCommentHistory(Address addr, int commentType) {
		lock.acquire();
		try {

			// records are sorted by date ascending						
			List<DBRecord> allRecords = getHistoryRecords(addr, commentType);

			List<CommentHistory> results = new ArrayList<>();
			String comment = getComment(addr, commentType);
			while (!allRecords.isEmpty()) {

				DBRecord rec = allRecords.get(allRecords.size() - 1);
				long date = rec.getLongValue(CommentHistoryAdapter.HISTORY_DATE_COL);
				List<DBRecord> records = subListByDate(allRecords, date);

				List<StringDiff> diffs = new ArrayList<>(records.size());

				String user = null;
				for (DBRecord r : records) {
					user = r.getString(CommentHistoryAdapter.HISTORY_USER_COL);
					int pos1 = r.getIntValue(CommentHistoryAdapter.HISTORY_POS1_COL);
					int pos2 = r.getIntValue(CommentHistoryAdapter.HISTORY_POS2_COL);
					String data = r.getString(CommentHistoryAdapter.HISTORY_STRING_COL);
					diffs.add(StringDiff.restore(data, pos1, pos2));
				}

				results.add(new CommentHistory(addr, commentType, user, comment, new Date(date)));
				comment = StringDiffUtils.applyDiffs(comment, diffs);

				records.clear(); // remove the subList elements from the list
			}

			CommentHistory[] h = new CommentHistory[results.size()];
			return results.toArray(h);
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return new CommentHistory[0];
	}

	// note: you must have the lock when calling this method
	private List<DBRecord> getHistoryRecords(Address addr, int commentType) throws IOException {
		RecordIterator it = historyAdapter.getRecordsByAddress(addr);
		List<DBRecord> list = new ArrayList<>();
		while (it.hasNext()) {
			DBRecord rec = it.next();
			if (rec.getByteValue(CommentHistoryAdapter.HISTORY_TYPE_COL) == commentType) {
				list.add(rec);
			}
		}
		return list;
	}

	// note: records are sorted by date; assume that the date we seek is at the end
	private List<DBRecord> subListByDate(List<DBRecord> records, long date) {

		for (int i = records.size() - 1; i >= 0; i--) {
			DBRecord rec = records.get(i);
			if (date != rec.getLongValue(CommentHistoryAdapter.HISTORY_DATE_COL)) {
				return records.subList(i + 1, records.size());
			}
		}

		// all records have the same date
		return records.subList(0, records.size());
	}

	private String getComment(Address addr, int commentType) throws IOException {
		DBRecord record = commentAdapter.getRecord(addrMap.getKey(addr, false));
		if (record != null) {
			return record.getString(commentType);
		}
		return "";
	}

	public void replaceDataTypes(long oldDataTypeID, long newDataTypeID) {
		lock.acquire();
		try {
			RecordIterator it = dataAdapter.getRecords();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				long id = rec.getLongValue(DataDBAdapter.DATA_TYPE_ID_COL);
				if (id == oldDataTypeID) {
					rec.setLongValue(DataDBAdapter.DATA_TYPE_ID_COL, newDataTypeID);
					dataAdapter.putRecord(rec);
					Address addr = addrMap.decodeAddress(rec.getKey());
					program.setChanged(ChangeManager.DOCR_CODE_REPLACED, addr, addr, null, null);
				}
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			cache.invalidate();
			lock.release();
		}
	}

	/**
	 * Add comment history records for comments being deleted.
	 * @param start start address
	 * @param end end address
	 * @throws IOException
	 */
	private void addCommentHistoryRecords(Address start, Address end) throws IOException {
		RecordIterator iter = commentAdapter.getRecords(start, end, true);
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			addCommentHistoryRecord(rec, CodeUnit.PRE_COMMENT);
			addCommentHistoryRecord(rec, CodeUnit.POST_COMMENT);
			addCommentHistoryRecord(rec, CodeUnit.EOL_COMMENT);
			addCommentHistoryRecord(rec, CodeUnit.PLATE_COMMENT);
			addCommentHistoryRecord(rec, CodeUnit.REPEATABLE_COMMENT);
		}
	}

	private void addCommentHistoryRecord(DBRecord commentRec, int commentType) {
		String comment = commentRec.getString(commentType);
		if (comment != null) {
			createCommentHistoryRecord(addrMap.decodeAddress(commentRec.getKey()), commentType,
				comment, "");
		}
	}

	private HashMap<Long, Byte> redisassmblyFlags;

	/**
	 * Complete language transformation of all instructions.  All existing prototypes will
	 * be discarded and all instructions redisassembled following flow and adjusting context as needed.
	 * Instructions which fail to redisassemble will be marked - since only one byte will be skipped, such bad
	 * instruction disassembly may cause subsequent errors due to possible instruction shift.
	 * This method is only intended for use by the ProgramDB setLanguage method which must ensure that 
	 * the context has been properly initialized.
	 * @param monitor task monitor
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if the operation is canceled.
	 */
	public void reDisassembleAllInstructions(TaskMonitor monitor)
			throws IOException, CancelledException {

		redisassemblyMode = true;
		try {
			if (lock.getOwner() != Thread.currentThread()) {
				throw new IllegalStateException("Must be invoked by lock owner");
			}

			Disassembler.clearUnimplementedPcodeWarnings(program, null, monitor);
			Disassembler.clearBadInstructionErrors(program, null, monitor);

			int maxCount = instAdapter.getRecordCount();
			monitor.initialize(maxCount);
			monitor.setMessage("Preparing for Re-Disassembly...");

			redisassmblyFlags = new HashMap<>();

			HashMap<Integer, Integer> protoLengthCache = new HashMap<>();
			AddressSet codeSet = new AddressSet();

			Address minAddr = null;
			Address maxAddr = null;

			int count = 0;
			RecordIterator recIter = instAdapter.getRecords();
			while (recIter.hasNext()) {
				DBRecord rec = recIter.next();

				Address addr = addrMap.decodeAddress(rec.getKey());
				if (minAddr == null) {
					minAddr = addr;
				}
				else {
					Address nextAddr = null;
					try {
						nextAddr = maxAddr.add(1);
					}
					catch (AddressOutOfBoundsException e) {
						// nextAddr will be null
					}
					if (nextAddr == null || !addr.equals(nextAddr)) {
						codeSet.addRange(minAddr, maxAddr);
						minAddr = addr;
					}
				}

				int protoId = rec.getIntValue(InstDBAdapter.PROTO_ID_COL);
				Integer len = protoLengthCache.get(protoId);
				if (len == null) {
					len = protoMgr.getOriginalPrototypeLength(protoId);
					if (len <= 0) {
						len = 1; // just in-case
					}
					protoLengthCache.put(protoId, len);
				}

				maxAddr = addr;
				try {
					maxAddr = addr.add(len - 1);
				}
				catch (AddressOutOfBoundsException e) {
					// maxAddr will equals addr
				}

				byte flags = rec.getByteValue(InstDBAdapter.FLAGS_COL);
				if (flags != 0) {
					redisassmblyFlags.put(rec.getKey(), flags);
				}

				if ((++count % 1000) == 0) {
					monitor.checkCanceled();
					monitor.setProgress(count);
				}
			}

			if (minAddr != null) {
				codeSet.addRange(minAddr, maxAddr);
			}

			monitor.setMessage("Clearing Old Instructions...");
			monitor.initialize(0);

			instAdapter.deleteAll();
			cache.invalidate();
			protoMgr.setLanguage(program.getLanguage());

			monitor.setMessage("Performing Re-Disassembly...");
			Disassembler d =
				Disassembler.getDisassembler(program, monitor, new DisassemblerMessageListener() {
					@Override
					public void disassembleMessageReported(String msg) {
						Msg.warn(this, msg);
					}
				});
			d.disassemble(codeSet, codeSet, true);

		}
		finally {
			redisassemblyMode = false;
			redisassmblyFlags = null;
		}

	}

	/**
	 * @param newProtoID
	 * @return
	 */
	InstructionPrototype getInstructionPrototype(int protoID) {
		return protoMgr.getPrototype(protoID);
	}

}
