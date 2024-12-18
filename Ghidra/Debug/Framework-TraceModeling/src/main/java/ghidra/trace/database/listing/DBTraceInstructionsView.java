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
package ghidra.trace.database.listing;

import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.program.database.code.InstructionDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.lang.InstructionError.InstructionErrorType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.database.context.DBTraceRegisterContextManager;
import ghidra.trace.database.context.DBTraceRegisterContextSpace;
import ghidra.trace.database.guest.InternalTracePlatform;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.model.*;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.listing.*;
import ghidra.trace.model.memory.TraceMemoryOperations;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.util.*;
import ghidra.util.LockHold;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The implementation of {@link TraceCodeSpace#instructions()}
 */
public class DBTraceInstructionsView extends AbstractBaseDBTraceDefinedUnitsView<DBTraceInstruction>
		implements TraceInstructionsView, InternalTraceBaseDefinedUnitsView<TraceInstruction> {

	protected static <T> T replaceIfNotNull(T cur, T rep) {
		return rep != null ? rep : cur;
	}

	/**
	 * A mechanism for adding a block of instructions
	 */
	protected class InstructionBlockAdder {
		private final Set<Address> skipDelaySlots;
		private final Lifespan lifespan;
		private final InternalTracePlatform platform;
		private final InstructionBlock block;
		private final Address errorAddress;
		private final InstructionError conflict;
		private final CodeUnit conflictCodeUnit;
		private final boolean overwrite;

		protected int count = 0;

		/**
		 * Construct an adder
		 * 
		 * <p>
		 * This should only be done after the entire instruction set has been checked
		 * 
		 * @param skipDelaySlots addresses of delay slotted instructions to skip
		 * @param lifespan the lifespan for each instruction
		 * @param platform the platform (language, compiler) for the instructions
		 * @param block the block to add
		 * @param errorAddress the address of the first error in the block, if any
		 * @param conflict a description of the error, if any
		 * @param conflictCodeUnit if a conflict, the code unit that already exists
		 * @param overwrite true to overwrite existing defined units
		 */
		private InstructionBlockAdder(Set<Address> skipDelaySlots, Lifespan lifespan,
				InternalTracePlatform platform, InstructionBlock block, Address errorAddress,
				InstructionError conflict, CodeUnit conflictCodeUnit, boolean overwrite) {
			this.skipDelaySlots = skipDelaySlots;
			this.lifespan = lifespan;
			this.platform = platform;
			this.block = block;
			this.errorAddress = errorAddress;
			this.conflict = conflict;
			this.conflictCodeUnit = conflictCodeUnit;
			this.overwrite = overwrite;
		}

		protected void truncateOrDelete(TraceInstruction exists) {
			if (exists.getStartSnap() < lifespan.lmin()) {
				exists.setEndSnap(lifespan.lmin() - 1);
			}
			else {
				exists.delete();
			}
		}

		protected boolean isSuitable(Instruction candidate, Instruction protoInstr) {
			try {
				return candidate.getPrototype().equals(protoInstr.getPrototype()) &&
					candidate.isFallThroughOverridden() == protoInstr.isFallThroughOverridden() &&
					Objects.equals(candidate.getFallThrough(), protoInstr.getFallThrough()) &&
					candidate.getFlowOverride() == protoInstr.getFlowOverride() &&
					candidate.getLength() == protoInstr.getLength() && // handles potential length override
					hasSameBytes(candidate, protoInstr);
			}
			catch (MemoryAccessException e) {
				throw new AssertionError(e);
			}
		}

		private boolean hasSameBytes(Instruction instr1, Instruction instr2)
				throws MemoryAccessException {
			return Arrays.equals(instr1.getParsedBytes(), instr2.getParsedBytes());
		}

		protected Instruction doAdjustExisting(Address address, Instruction protoInstr)
				throws AddressOverflowException, CancelledException, CodeUnitInsertionException {
			DBTraceInstruction exists = getAt(lifespan.lmin(), address);
			if (exists == null || exists.getLength() != protoInstr.getLength()) {
				AddressRange range =
					new AddressRangeImpl(protoInstr.getAddress(), protoInstr.getLength());
				space.definedUnits.clear(lifespan, range, false, TaskMonitor.DUMMY);
				return null;
			}
			if (!isSuitable(exists, protoInstr)) {
				truncateOrDelete(exists);
				return null;
			}
			long curEnd = exists.getEndSnap();
			if (curEnd < lifespan.lmax()) {
				AddressRange range =
					new AddressRangeImpl(protoInstr.getAddress(), protoInstr.getLength());
				long endSnap = computeTruncatedMax(lifespan, exists, range);
				exists.setEndSnap(endSnap);
			}
			return exists;
		}

		/**
		 * Check the preceding unit and see if it can be extended to "create" the desired one
		 * 
		 * <p>
		 * For overwrite, the caller should first use
		 * {@link #doAdjustExisting(Address, InstructionPrototype, Instruction)}.
		 * 
		 * @param address the starting address of the instruction
		 * @param protoInstr the prototype instruction
		 * @return the extended instruction, if it was a match
		 * @throws AddressOverflowException should never
		 * @throws CodeUnitInsertionException if there's no room to extend the preceding unit
		 */
		protected Instruction doExtendPreceding(Address address, Instruction protoInstr)
				throws AddressOverflowException, CodeUnitInsertionException {
			if (!lifespan.minIsFinite()) {
				return null;
			}
			DBTraceInstruction prec = getAt(lifespan.lmin() - 1, address);
			if (prec == null || prec.getLength() != protoInstr.getLength()) {
				return null;
			}
			if (!isSuitable(prec, protoInstr)) {
				return null;
			}
			AddressRange range =
				new AddressRangeImpl(protoInstr.getAddress(), protoInstr.getLength());
			long endSnap = computeTruncatedMax(lifespan, prec, range);
			if (!lifespan.contains(endSnap)) {
				// We can't extend it far enough
				return null;
			}
			prec.setEndSnap(endSnap);
			return prec;
		}

		/**
		 * Store the given instruction in the database
		 * 
		 * @param address the address of the instruction
		 * @param protoInstr the parsed (usually pseudo) instruction
		 * @return the created instruction
		 */
		protected Instruction doCreateInstruction(Address address, Instruction protoInstr) {
			try {
				if (overwrite) {
					Instruction exists = doAdjustExisting(address, protoInstr);
					if (exists != null) {
						return exists;
					}
				}

				Instruction prec = doExtendPreceding(address, protoInstr);
				if (prec != null) {
					return prec;
				}

				Instruction created = doCreate(lifespan, address, platform,
					protoInstr.getPrototype(), protoInstr, protoInstr.getLength());
				// copy override settings to replacement instruction
				if (protoInstr.isFallThroughOverridden()) {
					created.setFallThrough(protoInstr.getFallThrough());
				}
				FlowOverride flowOverride = protoInstr.getFlowOverride();
				if (flowOverride != FlowOverride.NONE) {
					created.setFlowOverride(flowOverride);
				}
				return created;
			}
			catch (AddressOverflowException | // End address already checked via protoInstr
					CodeUnitInsertionException | // We've already checked for conflicts
					CancelledException e) { // There's no monitor to cancel
				throw new AssertionError(e);
			}
		}

		/**
		 * Adds the instructions and returns the last instruction added
		 * 
		 * <p>
		 * If it encounters a delay-slotted instruction, it will recurse on the group, iterating in
		 * reverse order.
		 * 
		 * @param instructions the instructions to add
		 * @param areDelaySlots true if the instructions are already reversed from being
		 *            delay-slotted
		 * @return the last instruction added
		 */
		protected Instruction doAddInstructions(Iterator<Instruction> it, boolean areDelaySlots) {
			Instruction lastInstruction = null;
			while (it.hasNext()) {
				Instruction protoInstr = it.next();
				Address startAddress = protoInstr.getAddress();
				try {
					// If there's an actual conflict, terminate before placing this unit
					// If it's a disassembly error, we will place the unit then terminate.
					if (conflictCodeUnit != null) { // implies errorAddress != null
						if (errorAddress.compareTo(
							DBTraceCodeManager.instructionMax(protoInstr, false)) <= 0) {
							Address flowFromAddress =
								lastInstruction != null ? lastInstruction.getAddress()
										: block.getFlowFromAddress();
							block.setCodeUnitConflict(conflict.getConflictAddress(), startAddress,
								flowFromAddress, conflict.isInstructionConflict(), false);
							return lastInstruction;
						}
						if (errorAddress.compareTo(
							DBTraceCodeManager.instructionMax(protoInstr, true)) <= 0) {
							// TODO: We won't record it...? Seems wrong.
							// Maybe already recorded?
							return lastInstruction;
						}
					}
				}
				catch (AddressOverflowException e) {
					return lastInstruction; // Delay slots extend beyond memory space.
				}

				if (!skipDelaySlots.contains(startAddress)) {
					if (!areDelaySlots && protoInstr.getPrototype().hasDelaySlots()) {
						// Reverse their order then add them. This ensures pcode can be generated
						// for the delay-slotted instruction upon its creation.
						Deque<Instruction> delayed =
							new ArrayDeque<>(protoInstr.getDelaySlotDepth());
						for (int i = delayed.size(); i >= 0 && it.hasNext(); i--) {
							delayed.push(it.next());
						}
						lastInstruction = replaceIfNotNull(lastInstruction,
							doAddInstructions(delayed.iterator(), true));
					}
					lastInstruction = doCreateInstruction(startAddress, protoInstr);
				}
				if (errorAddress != null && conflictCodeUnit == null &&
					errorAddress.compareTo(startAddress) <= 0) {
					// The disassembly error will be placed, but the remainder is skipped
					return lastInstruction;
				}
			}
			return lastInstruction;
		}

		/**
		 * Add the instructions and return the last one added
		 * 
		 * @return the last instruction added
		 */
		protected Instruction doAddInstructions() {
			return doAddInstructions(block.iterator(), false);
		}
	}

	/**
	 * Construct the view
	 * 
	 * @param space the space, bound to an address space
	 */
	public DBTraceInstructionsView(DBTraceCodeSpace space) {
		super(space, space.instructionMapSpace);
	}

	/**
	 * Set the context over the given box
	 * 
	 * <p>
	 * If the given context matches the language's default at the mininum address of the box, the
	 * context is cleared.
	 * 
	 * @param tasr the box
	 * @param language the language for the instruction
	 * @param context the desired context
	 */
	protected void doSetContext(TraceAddressSnapRange tasr, Language language,
			ProcessorContextView context) {
		Register contextReg = language.getContextBaseRegister();
		if (contextReg == null || contextReg == Register.NO_CONTEXT) {
			return;
		}
		RegisterValue newValue = context.getRegisterValue(contextReg);
		DBTraceRegisterContextManager ctxMgr = space.trace.getRegisterContextManager();
		if (Objects.equals(ctxMgr.getDefaultValue(language, contextReg, tasr.getX1()), newValue)) {
			DBTraceRegisterContextSpace ctxSpace = ctxMgr.get(space, false);
			if (ctxSpace == null) {
				return;
			}
			ctxSpace.removeValue(language, contextReg, tasr.getLifespan(), tasr.getRange());
			return;
		}
		DBTraceRegisterContextSpace ctxSpace = ctxMgr.get(space, true);
		// TODO: Do not save non-flowing context beyond???
		ctxSpace.setValue(language, newValue, tasr.getLifespan(), tasr.getRange());
	}

	/**
	 * Create an instruction
	 * 
	 * @param lifespan the lifespan of the instruction
	 * @param address the minimum address of the instruction
	 * @param platform the platform (language, compiler) for the instruction
	 * @param prototype the instruction's prototype
	 * @param context the initial context for parsing the instruction
	 * @param length instruction byte-length (must be in the range 0..prototype.getLength()). If
	 *            smaller than the prototype length it must have a value no greater than 7,
	 *            otherwise an error will be thrown. A value of 0 or greater-than-or-equal the
	 *            prototype length will be ignored and not impose and override length. The length
	 *            value must be a multiple of the {@link Language#getInstructionAlignment()
	 *            instruction alignment} .
	 * @return the newly created instruction.
	 * @throws CodeUnitInsertionException thrown if the new Instruction would overlap and existing
	 *             {@link CodeUnit} or the specified {@code length} is unsupported.
	 * @throws IllegalArgumentException if a negative {@code length} is specified.
	 * @throws AddressOverflowException if the instruction would fall off the address space
	 */
	protected DBTraceInstruction doCreate(Lifespan lifespan, Address address,
			InternalTracePlatform platform, InstructionPrototype prototype,
			ProcessorContextView context, int length)
			throws CodeUnitInsertionException, AddressOverflowException {
		if (platform.getLanguage() != prototype.getLanguage()) {
			throw new IllegalArgumentException("Platform and prototype disagree in language");
		}

		int forcedLengthOverride = InstructionDB.checkLengthOverride(length, prototype);
		if (length == 0) {
			length = prototype.getLength();
		}
		Address endAddress = address.addNoWrap(length - 1);
		AddressRangeImpl createdRange = new AddressRangeImpl(address, endAddress);

		// Truncate, then check that against existing code units.
		long endSnap = computeTruncatedMax(lifespan, null, createdRange);
		TraceAddressSnapRange tasr =
			new ImmutableTraceAddressSnapRange(createdRange, lifespan.withMax(endSnap));

		if (!space.undefinedData.coversRange(tasr)) {
			// TODO: Figure out the conflicting unit or snap boundary?
			throw new CodeUnitInsertionException("Code units cannot overlap");
		}

		doSetContext(tasr, prototype.getLanguage(), context);

		DBTraceInstruction created = space.instructionMapSpace.put(tasr, null);
		created.set(platform, prototype, context, forcedLengthOverride);

		cacheForContaining.notifyNewEntry(tasr.getLifespan(), createdRange, created);
		cacheForSequence.notifyNewEntry(tasr.getLifespan(), createdRange, created);
		space.undefinedData.invalidateCache();

		// TODO: Save the context register into the context manager? Flow it?
		// TODO: Ensure cached undefineds don't extend into defined stuff
		// TODO: Explicitly remove undefined from cache, or let weak refs take care of it?
		return created;
	}

	@Override
	public DBTraceInstruction create(Lifespan lifespan, Address address, TracePlatform platform,
			InstructionPrototype prototype, ProcessorContextView context, int forcedLengthOverride)
			throws CodeUnitInsertionException {
		InternalTracePlatform dbPlatform = space.manager.platformManager.assertMine(platform);
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			DBTraceInstruction created =
				doCreate(lifespan, address, dbPlatform, prototype, context, forcedLengthOverride);
			space.trace.setChanged(
				new TraceChangeRecord<>(TraceEvents.CODE_ADDED, space, created, created));
			return created;
		}
		catch (AddressOverflowException e) {
			throw new CodeUnitInsertionException("Code unit would extend beyond address space");
		}
	}

	/**
	 * Prepare to check a block for conflicts
	 * 
	 * @param startSnap the minimum snap for each instruction
	 * @param block the block of instructions
	 * @return an iterator for overlapping object pairs
	 */
	protected OverlappingObjectIterator<Instruction, CodeUnit> startCheckingBlock(long startSnap,
			InstructionBlock block) {
		Address startAddress = block.getStartAddress();
		CodeUnit found = space.definedUnits.getContaining(startSnap, startAddress);
		if (found != null) {
			startAddress = found.getAddress();
		}
		Iterator<Instruction> instructions = block.iterator();
		Iterator<? extends AbstractDBTraceCodeUnit<?>> existing =
			space.definedUnits.get(startSnap, startAddress, true).iterator();
		return new OverlappingObjectIterator<Instruction, CodeUnit>(instructions,
			OverlappingObjectIterator.CODE_UNIT, existing, OverlappingObjectIterator.CODE_UNIT);
	}

	/**
	 * Start adding the given block to the database
	 * 
	 * <p>
	 * If this returns non-null, it should be immediately followed by
	 * {@link InstructionBlockAdder#doAddInstructions()}.
	 * 
	 * @param lifespan the lifespan of each instruction
	 * @param skipDelaySlots the addresses of delay-slotted instructions to skip
	 * @param platform the instructions' platform (language, compiler)
	 * @param block the block of instructions to add
	 * @param overwrite true to overwrite existing defined units
	 * @return the adder, or null
	 */
	protected InstructionBlockAdder startAddingBlock(Lifespan lifespan, Set<Address> skipDelaySlots,
			InternalTracePlatform platform, InstructionBlock block, boolean overwrite) {
		if (overwrite) {
			return new InstructionBlockAdder(skipDelaySlots, lifespan, platform, block, null, null,
				null, overwrite);
		}
		InstructionError conflict = block.getInstructionConflict();
		if (conflict == null) {
			return new InstructionBlockAdder(skipDelaySlots, lifespan, platform, block, null, null,
				null, overwrite);
		}
		Address errorAddress = conflict.getInstructionAddress();
		if (errorAddress == null) {
			return null; // The whole block is considered in error
		}
		if (!conflict.getInstructionErrorType().isConflict) {
			return new InstructionBlockAdder(skipDelaySlots, lifespan, platform, block,
				errorAddress, conflict, null, overwrite);
		}
		long startSnap = lifespan.lmin();
		CodeUnit conflictCodeUnit =
			space.definedUnits.getAt(startSnap, conflict.getConflictAddress());
		return new InstructionBlockAdder(skipDelaySlots, lifespan, platform, block, errorAddress,
			conflict, conflictCodeUnit, overwrite);
	}

	protected boolean isKnown(DBTraceMemorySpace ms, long snap, CodeUnit cu) {
		if (ms == null) {
			return false;
		}
		AddressRange range = new AddressRangeImpl(cu.getMinAddress(), cu.getMaxAddress());
		var states = ms.getStates(snap, range);
		return TraceMemoryOperations.isStateEntirely(range, states, TraceMemoryState.KNOWN);
	}

	/**
	 * Checks the intended locations for conflicts with existing units.
	 * 
	 * <p>
	 * This also clears locations where delay slots will be replacing non-delay slots.
	 * {@code skipDelaySlots} will be populated with any existing delay slot locations which should
	 * not be overwritten
	 * 
	 * @param instructionSet the instruction set to examine
	 * @param skipDelaySlots an empty mutable set to be populated
	 */
	protected void checkInstructionSet(long startSnap, InstructionSet instructionSet,
			Set<Address> skipDelaySlots) {
		// NOTE: Partly derived from CodeManager#checkInstructionSet()
		// Attempted to factor more fluently
		DBTraceMemoryManager mm = space.trace.getMemoryManager();
		for (InstructionBlock block : instructionSet) {
			// If block contains a known error, record its address, and do not proceed beyond it
			Address errorAddress = null;
			// See if this block has already been pruned due to errors in upstream blocks
			InstructionError conflict = block.getInstructionConflict();
			if (conflict != null) {
				errorAddress = conflict.getInstructionAddress();
				if (errorAddress == null) {
					// Assume the whole block is messed up, and skip it.
					continue;
				}
			}
			if (block.isEmpty()) {
				continue; // nothing to iterate over anyway, so skip it.
			}

			// Flow into first instruction is flow into block
			// After this, each time the protoInstr is stepped,
			// we update flow to preceding instruction address
			Address flowFromAddress = block.getFlowFromAddress();
			Instruction lastProtoInstr = null;
			Iterator<Pair<Instruction, CodeUnit>> overlapIt = startCheckingBlock(startSnap, block);
			while (overlapIt.hasNext()) {
				Pair<Instruction, CodeUnit> overlap = overlapIt.next();
				Instruction protoInstr = overlap.getLeft();
				if (errorAddress != null && protoInstr.getAddress().compareTo(errorAddress) >= 0) {
					break; // do not proceed beyond disassembly errors
				}
				if (lastProtoInstr != protoInstr) {
					flowFromAddress = protoInstr.getAddress();
					lastProtoInstr = protoInstr;
				}
				CodeUnit existsCu = overlap.getRight();
				DBTraceMemorySpace ms =
					mm.getMemorySpace(existsCu.getAddress().getAddressSpace(), false);
				if (!isKnown(ms, startSnap, existsCu) && existsCu instanceof TraceCodeUnit tcu) {
					tcu.delete();
					continue;
				}
				int cmp = existsCu.getMinAddress().compareTo(protoInstr.getMinAddress());
				boolean existsIsInstruction = (existsCu instanceof TraceInstruction);
				if (cmp == 0 && existsIsInstruction) {
					TraceInstruction existsInstr = (TraceInstruction) existsCu;
					if (protoInstr.isInDelaySlot() != existsInstr.isInDelaySlot() &&
						protoInstr.getLength() == existsInstr.getLength()) {
						if (protoInstr.isInDelaySlot()) {
							// allow the delay-slot protoInstr to overwrite the existsInstr
							existsInstr.delete();
						}
						else {
							// Likely caused by odd flow into delay slot - assume OK
							// Do not allow the non delay-slot protoInstr to overwrite!
							skipDelaySlots.add(existsInstr.getAddress());
						}
						continue;
					}
					if (!protoInstr.getPrototype().equals(existsInstr.getPrototype())) {
						InstructionError.dumpInstructionDifference(protoInstr, existsInstr);
						block.setInconsistentPrototypeConflict(existsInstr.getAddress(),
							flowFromAddress);
					}
					else {
						// Mark block as overlapping existing code
						// NOTE: This seems to include when protoInstr and existsInstr match
						block.setInstructionError(InstructionErrorType.DUPLICATE,
							protoInstr.getAddress(), existsInstr.getAddress(), flowFromAddress,
							null);
					}
					break; // next block (skip remainder of this one)
				}
				// NOTE: existsIsInstruction implies cmp != 0, so record as off-cut conflict
				block.setCodeUnitConflict(existsCu.getAddress(), protoInstr.getAddress(),
					flowFromAddress, existsIsInstruction, true);
			}
		}
	}

	@Override
	public AddressSetView addInstructionSet(Lifespan lifespan, TracePlatform platform,
			InstructionSet instructionSet, boolean overwrite) {
		InternalTracePlatform dbPlatform = space.manager.platformManager.assertMine(platform);
		// NOTE: Partly derived from CodeManager#addInstructions()
		// Attempted to factor more fluently
		AddressSet result = new AddressSet();
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			long startSnap = lifespan.lmin();
			Set<Address> skipDelaySlots = new HashSet<>();
			if (!overwrite) {
				checkInstructionSet(startSnap, instructionSet, skipDelaySlots);
			}

			// Add blocks
			for (InstructionBlock block : instructionSet) {
				InstructionBlockAdder adder =
					startAddingBlock(lifespan, skipDelaySlots, dbPlatform, block, overwrite);
				if (adder == null) {
					continue;
				}
				Instruction lastInstruction = adder.doAddInstructions();
				block.setInstructionsAddedCount(adder.count);
				if (lastInstruction != null) {
					Address maxAddress = DBTraceCodeManager.instructionMax(lastInstruction, true);
					result.addRange(block.getStartAddress(), maxAddress);
					space.trace.setChanged(new TraceChangeRecord<>(TraceEvents.CODE_ADDED, space,
						new ImmutableTraceAddressSnapRange(block.getStartAddress(), maxAddress,
							lifespan)));
				}
			}
			return result;
		}
		catch (AddressOverflowException e) {
			// Better have skipped any delay-slotted instructions whose delays overflowed
			throw new AssertionError(e);
		}
	}
}
