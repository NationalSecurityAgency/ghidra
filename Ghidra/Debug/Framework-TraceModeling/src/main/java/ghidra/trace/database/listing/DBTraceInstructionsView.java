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

import org.apache.commons.lang3.tuple.Pair;

import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.lang.InstructionError.InstructionErrorType;
import ghidra.program.model.listing.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.Trace.TraceCodeChangeType;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.listing.TraceInstruction;
import ghidra.trace.model.listing.TraceInstructionsView;
import ghidra.trace.util.OverlappingObjectIterator;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DBTraceInstructionsView extends AbstractBaseDBTraceDefinedUnitsView<DBTraceInstruction>
		implements TraceInstructionsView {

	protected static <T> T replaceIfNotNull(T cur, T rep) {
		return rep != null ? rep : cur;
	}

	protected class InstructionBlockAdder {
		private final Set<Address> skipDelaySlots;
		private final InstructionBlock block;
		private final Address errorAddress;
		private final InstructionError conflict;
		private final CodeUnit conflictCodeUnit;

		protected int count = 0;

		private InstructionBlockAdder(Set<Address> skipDelaySlots, InstructionBlock block,
				Address errorAddress, InstructionError conflict, CodeUnit conflictCodeUnit) {
			this.skipDelaySlots = skipDelaySlots;
			this.block = block;
			this.errorAddress = errorAddress;
			this.conflict = conflict;
			this.conflictCodeUnit = conflictCodeUnit;
		}

		protected Instruction doCreateInstruction(Range<Long> lifespan, Address address,
				InstructionPrototype prototype, Instruction protoInstr) {
			try {
				Instruction created = doCreate(lifespan, address, prototype, protoInstr);
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
			catch (CodeUnitInsertionException | AddressOverflowException e) {
				// End address already computed when protoInstr created.
				// We've also already checked for conflicts
				throw new AssertionError(e);
			}
		}

		/**
		 * Adds the instructions and returns the last instruction added
		 * 
		 * If it encounters a delay-slotted instruction, it will recurse on the group, iterating in
		 * reverse order.
		 * 
		 * @param instructions
		 * @param areDelaySlots
		 * @return
		 */
		protected Instruction doAddInstructions(Range<Long> lifespan, Iterator<Instruction> it,
				boolean areDelaySlots) {
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
					InstructionPrototype prototype = protoInstr.getPrototype();
					if (!areDelaySlots && prototype.hasDelaySlots()) {
						// Reverse their order then add them. This ensures pcode can be generated
						// for the delay-slotted instruction upon its creation.
						Deque<Instruction> delayed =
							new ArrayDeque<>(protoInstr.getDelaySlotDepth());
						for (int i = delayed.size(); i >= 0 && it.hasNext(); i--) {
							delayed.push(it.next());
						}
						lastInstruction = replaceIfNotNull(lastInstruction,
							doAddInstructions(lifespan, delayed.iterator(), true));
					}
					else {
						lastInstruction =
							doCreateInstruction(lifespan, startAddress, prototype, protoInstr);
					}
				}
				if (errorAddress != null && conflictCodeUnit == null &&
					errorAddress.compareTo(startAddress) <= 0) {
					// The disassembly error will be placed, but the remainder is skipped
					return lastInstruction;
				}
			}
			return lastInstruction;
		}
	}

	public DBTraceInstructionsView(DBTraceCodeSpace space) {
		super(space, space.instructionMapSpace);
	}

	protected DBTraceInstruction doCreate(Range<Long> lifespan, Address address,
			InstructionPrototype prototype, ProcessorContextView context)
			throws CodeUnitInsertionException, AddressOverflowException {
		Address endAddress = address.addNoWrap(prototype.getLength() - 1);
		AddressRangeImpl createdRange = new AddressRangeImpl(address, endAddress);

		// First, truncate lifespan to the next unit in the range, if end is unbounded
		if (!lifespan.hasUpperBound()) {
			lifespan = space.instructions.truncateSoonestDefined(lifespan, createdRange);
			lifespan = space.definedData.truncateSoonestDefined(lifespan, createdRange);
		}

		// Second, truncate lifespan to the next change of bytes in the range
		// Then, check that against existing code units.
		DBTraceMemorySpace memSpace =
			space.trace.getMemoryManager().getMemorySpace(space.space, true);
		long endSnap = memSpace.getFirstChange(lifespan, createdRange);
		if (endSnap == Long.MIN_VALUE) {
			endSnap = DBTraceUtils.upperEndpoint(lifespan);
		}
		else {
			endSnap--;
		}
		TraceAddressSnapRange tasr = new ImmutableTraceAddressSnapRange(createdRange,
			DBTraceUtils.toRange(DBTraceUtils.lowerEndpoint(lifespan), endSnap));

		if (!space.undefinedData.coversRange(tasr)) {
			// TODO: Figure out the conflicting unit or snap boundary?
			throw new CodeUnitInsertionException("Code units cannot overlap");
		}

		DBTraceInstruction created = space.instructionMapSpace.put(tasr, null);
		created.set(prototype, context);

		cacheForContaining.notifyNewEntry(lifespan, createdRange, created);
		cacheForSequence.notifyNewEntry(lifespan, createdRange, created);
		space.undefinedData.invalidateCache();

		// TODO: Save the context register into the context manager? Flow it?
		// TODO: Ensure cached undefineds don't extend into defined stuff
		// TODO: Explicitly remove undefined from cache, or let weak refs take care of it?
		return created;
	}

	@Override
	public DBTraceInstruction create(Range<Long> lifespan, Address address,
			InstructionPrototype prototype, ProcessorContextView context)
			throws CodeUnitInsertionException {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			DBTraceInstruction created = doCreate(lifespan, address, prototype, context);
			space.trace.setChanged(new TraceChangeRecord<>(TraceCodeChangeType.ADDED,
				space, created, created));
			return created;
		}
		catch (AddressOverflowException e) {
			throw new CodeUnitInsertionException("Code unit would extend beyond address space");
		}
	}

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

	protected InstructionBlockAdder startAddingBlock(long startSnap, Set<Address> skipDelaySlots,
			InstructionBlock block) {
		InstructionError conflict = block.getInstructionConflict();
		if (conflict == null) {
			return new InstructionBlockAdder(skipDelaySlots, block, null, null, null);
		}
		Address errorAddress = conflict.getInstructionAddress();
		if (errorAddress == null) {
			return null; // The whole block is considered in error
		}
		if (!conflict.getInstructionErrorType().isConflict) {
			return new InstructionBlockAdder(skipDelaySlots, block, errorAddress, conflict, null);
		}
		CodeUnit conflictCodeUnit =
			space.definedUnits.getAt(startSnap, conflict.getConflictAddress());
		return new InstructionBlockAdder(skipDelaySlots, block, errorAddress, conflict,
			conflictCodeUnit);
	}

	/**
	 * Checks the intended locations for conflicts with existing units.
	 * 
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
					flowFromAddress, existsIsInstruction, existsIsInstruction);
			}
		}
	}

	@Override
	public AddressSetView addInstructionSet(Range<Long> lifespan, InstructionSet instructionSet,
			boolean overwrite) {
		// NOTE: Partly derived from CodeManager#addInstructions()
		// Attempted to factor more fluently
		AddressSet result = new AddressSet();
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			long startSnap = DBTraceUtils.lowerEndpoint(lifespan);
			Set<Address> skipDelaySlots = new HashSet<>();
			if (overwrite) {
				for (AddressRange range : instructionSet.getAddressSet()) {
					space.definedUnits.clear(lifespan, range, false, TaskMonitor.DUMMY);
				}
			}
			else {
				checkInstructionSet(startSnap, instructionSet, skipDelaySlots);
			}

			// Add blocks
			for (InstructionBlock block : instructionSet) {
				InstructionBlockAdder adder = startAddingBlock(startSnap, skipDelaySlots, block);
				if (adder == null) {
					continue;
				}
				Instruction lastInstruction =
					adder.doAddInstructions(lifespan, block.iterator(), false);
				block.setInstructionsAddedCount(adder.count);
				if (lastInstruction != null) {
					Address maxAddress = DBTraceCodeManager.instructionMax(lastInstruction, true);
					result.addRange(block.getStartAddress(), maxAddress);
					space.trace.setChanged(new TraceChangeRecord<>(TraceCodeChangeType.ADDED,
						space, new ImmutableTraceAddressSnapRange(
							block.getStartAddress(), maxAddress, lifespan)));
				}
			}
			return result;
		}
		catch (CancelledException e) {
			throw new AssertionError(e); // No actual monitor
		}
		catch (AddressOverflowException e) {
			// Better have skipped any delay-slotted instructions whose delays overflowed
			throw new AssertionError(e);
		}
	}
}
