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
package ghidra.program.model.lang;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionError.InstructionErrorType;
import ghidra.program.model.listing.Instruction;

/**
 * Represents a block of instructions.  Used as part of an InstructionSet to be added to the
 * program.
 *
 */
public class InstructionBlock implements Iterable<Instruction> {

	private boolean isStartOfFlow = false;
	private Address startAddr;
	private Address maxAddress;
	private Address flowFrom;
	private Address lastInstructionAddress;
	private Address fallthroughAddress;
	private LinkedHashMap<Address, Instruction> instructionMap =
		new LinkedHashMap<Address, Instruction>();
	private List<Address> flowAddresses = new ArrayList<Address>();
	private List<InstructionBlockFlow> blockFlows;
	private InstructionError instructionError;
	private int instructionsAddedCount;

	public InstructionBlock(Address startAddr) {
		this.startAddr = startAddr;
	}

	/**
	 * Allows the block to be tagged as start of flow to force
	 * InstructionSet iterator to treat as a flow start.
	 * This method should not be used after this block has
	 * been added to an InstructionSet
	 * @param isStart
	 */
	public void setStartOfFlow(boolean isStart) {
		isStartOfFlow = isStart;
	}

	/**
	 * @return true if this block should be treated as the start of a new 
	 * flow when added to a InstructionSet.
	 */
	public boolean isFlowStart() {
		return isStartOfFlow;
	}

	/**
	 * Returns the minimum/start address of the block;
	 * @return the minimum/start address of the block
	 */
	public Address getStartAddress() {
		return startAddr;
	}

	/**
	 * Returns the maximum address of the block, or null if the block is empty;
	 * @return the maximum address of the block.
	 */
	public Address getMaxAddress() {
		return maxAddress != null ? maxAddress : startAddr;
	}

	/**
	 * Returns the instruction at the specified address within this block
	 * @param address
	 * @return instruction at the specified address within this block or null if not found
	 */
	public Instruction getInstructionAt(Address address) {
		return instructionMap.get(address);
	}

	/**
	 * Find the first instruction within this block which intersects the specified range.
	 * This method should be used sparingly since it uses a brute-force search.
	 * @param min the minimum intersection address
	 * @param max the maximum intersection address
	 * @return instruction within this block which intersects the specified range or null
	 * if not found 
	 */
	public Instruction findFirstIntersectingInstruction(Address min, Address max) {
		Instruction intersectInstr = null;
		for (Instruction instr : instructionMap.values()) {
			Address instrMin = instr.getMinAddress();
			if (instrMin.compareTo(max) > 0) {
				continue;
			}
			Address instrMax = instr.getMaxAddress();
			if (instrMax.compareTo(min) < 0) {
				continue;
			}
			if (intersectInstr != null && intersectInstr.getAddress().compareTo(instrMin) < 0) {
				continue;
			}
			intersectInstr = instr;
		}
		return intersectInstr;
	}

	@Override
	public String toString() {
		return "[ " + startAddr + (maxAddress != null ? ("-" + maxAddress) : ": <empty>") + "]";
	}

	/**
	 * Adds an instruction to this block.  If the block in not empty, the newly added instruction
	 * must be directly after the current block maximum address.  In other words, all instructions
	 * int the block must be consecutive.
	 * @param instruction the instruction to add to this block.
	 * @throws IllegalArgumentException if the new instruction does not immediately follow the
	 * last instruction added.
	 */
	public void addInstruction(Instruction instruction) {
		Address instructionMinAddr = instruction.getMinAddress();
		if (maxAddress == null) {
			if (!instructionMinAddr.equals(startAddr)) {
				throw new IllegalArgumentException("First instruction to block had address " +
					instructionMinAddr + ", expected address " + startAddr);
			}
		}
		else if (!maxAddress.isSuccessor(instructionMinAddr)) {
			throw new IllegalArgumentException("Newly added instruction at address " +
				instructionMinAddr + " is not the immediate succesor to address " + maxAddress);
		}
		instructionMap.put(instructionMinAddr, instruction);
		if (!instruction.isInDelaySlot()) {
			lastInstructionAddress = instruction.getMinAddress();
		}
		maxAddress = instruction.getMaxAddress();
	}

	/**
	 * Add a block flow specified by a InstructionBlockFlow object.  These flows include all
	 * calls, branches and fall-throughs and may span across multiple InstructionSets and are
	 * not used by the block flow iterator within the associated InstructionSet.
	 * @param blockFlow block flow
	 */
	public void addBlockFlow(InstructionBlockFlow blockFlow) {
		if (blockFlows == null) {
			blockFlows = new ArrayList<InstructionBlockFlow>();
		}
		blockFlows.add(blockFlow);
	}

	/**
	 * Adds a branch type flow to this instruction block and is used by the block flow
	 * iterator of the associated InstructionSet.
	 * @param destinationAddress the destination of a branch type flow from this instruction block.
	 */
	public void addBranchFlow(Address destinationAddress) {
		flowAddresses.add(destinationAddress);
	}

	/**
	 * Sets the fall through address for this block and is used by the block flow
	 * iterator of the associated InstructionSet.  The fallthrough should not be 
	 * set if it is added as a block flow.
	 * @param fallthroughAddress the address of the fallthrough
	 */
	public void setFallThrough(Address fallthroughAddress) {
		this.fallthroughAddress = fallthroughAddress;
	}

	/**
	 * Returns a list of all the branch flows that were added to this instruction block
	 * and flow to other blocks within the associated InstructionSet.
	 * @return a list of all the branch flows that were added to this instruction block.
	 */
	public List<Address> getBranchFlows() {
		return flowAddresses;
	}

	/**
	 * Returns a list of all block flows that were added to this instruction block as
	 * a list of InstructionBlockFlow objects.  NOTE: These flows may not be contained 
	 * within the associated InstructionSet.
	 * @return a list of all flows that were added to this instruction block.
	 */
	public List<InstructionBlockFlow> getBlockFlows() {
		return blockFlows;
	}

	/**
	 * Returns the fallthrough address.  Null is returned if there is no fall through. 
	 * @return the fallthrough address.
	 */
	public Address getFallThrough() {
		return fallthroughAddress;
	}

	/**
	 * Sets this block to have an instruction error.  
	 * @param type The type of error/conflict. 
	 * @param intendedInstructionAddress address of intended instruction which failed to be created
	 * @param conflictAddress the address of the exiting code unit that is preventing the instruction in this
	 * block to be laid down (required for CODE_UNIT or DUPLCIATE conflict error).
	 * @param flowFromAddress the flow-from instruction address or null if unknown
	 * @param message - A message that describes the conflict to a user.
	 */
	public void setInstructionError(InstructionError.InstructionErrorType type,
			Address intendedInstructionAddress, Address conflictAddress, Address flowFromAddress,
			String message) {
		if (type == InstructionErrorType.PARSE) {
			throw new IllegalArgumentException("use setParseConflict for PARSE conflicts");
		}
		instructionError =
			new InstructionError(this, type, intendedInstructionAddress, conflictAddress,
				flowFromAddress, message);
	}

	/**
	 * Set instruction memory error
	 * @param instrAddr instruction address
	 * @param flowFromAddr flow-from address
	 * @param errorMsg
	 */
	public void setInstructionMemoryError(Address instrAddr, Address flowFromAddr, String errorMsg) {
		setInstructionError(InstructionErrorType.MEMORY, instrAddr, instrAddr, flowFromAddr,
			errorMsg);
	}

	/**
	 * Set inconsistent instruction prototype CODE_UNIT conflict
	 * @param instrAddr instruction addr where inconsistent prototype exists
	 * @param flowFromAddr flow-from address
	 */
	public void setInconsistentPrototypeConflict(Address instrAddr, Address flowFromAddr) {
		setInstructionError(InstructionErrorType.INSTRUCTION_CONFLICT, instrAddr, instrAddr,
			flowFromAddr, "Multiple flows produced inconsistent instruction prototype at " +
				instrAddr + " - possibly due to inconsistent context");
	}

	/**
	 * Set offcut-instruction or data CODE_UNIT conflict
	 * @param codeUnitAddr existing instruction/data address
	 * @param newInstrAddr new disassembled instruction address
	 * @param flowFromAddr flow-from address
	 * @param isInstruction true if conflict is due to offcut-instruction, otherwise data is assumed
	 * @param isOffcut true if conflict due to offcut instruction
	 */
	public void setCodeUnitConflict(Address codeUnitAddr, Address newInstrAddr,
			Address flowFromAddr, boolean isInstruction, boolean isOffcut) {
		// NOTE: CodeManager relies on conflict address being the address of the existing 
		// code unit which triggered the conflict - any conflict bookmark on an undefined code unit
		// runs the risk of becoming offcut within a subsequent larger code unit.
		InstructionErrorType errorType;
		if (isInstruction) {
			errorType =
				isOffcut ? InstructionErrorType.OFFCUT_INSTRUCTION
						: InstructionErrorType.INSTRUCTION_CONFLICT;
		}
		else {
			errorType = InstructionErrorType.DATA_CONFLICT;
		}
		setInstructionError(errorType, newInstrAddr, codeUnitAddr, flowFromAddr,
			"Failed to disassemble at " + newInstrAddr + " due to conflicting " +
				(isInstruction ? "instruction" : "data") + " at " + codeUnitAddr);
	}

	/**
	 * Sets this block to have a PARSE conflict which means that the instruction parse failed
	 * at the specified conflictAddress using the specified contextValue.  
	 * @param conflictAddress the address of the exiting code unit that is preventing the instruction in this
	 * block to be laid down.
	 * @param contextValue the context-register value used during the failed parse attempt
	 * @param flowFromAddress the flow-from instruction address or null
	 * @param message - A message that describes the conflict to a user.
	 */
	public void setParseConflict(Address conflictAddress, RegisterValue contextValue,
			Address flowFromAddress, String message) {
		instructionError =
			new InstructionError(this, contextValue, conflictAddress, flowFromAddress, message);
	}

	/**
	 * Clears any conflict associated with this block.
	 */
	public void clearConflict() {
		instructionError = null;
	}

	/**
	 * Returns the current conflict associated with this block.
	 * @return the current conflict associated with this block.
	 */
	public InstructionError getInstructionConflict() {
		return instructionError;
	}

	/**
	 * Returns an iterator over all the instructions in this block.
	 */
	@Override
	public Iterator<Instruction> iterator() {
		return instructionMap.values().iterator();
	}

	/**
	 * @return address of last instruction contained within this block
	 */
	public Address getLastInstructionAddress() {
		return lastInstructionAddress;
	}

	/**
	 * @return true if no instructions exist within this block
	 */
	public boolean isEmpty() {
		return instructionMap.isEmpty();
	}

	/**
	 * @return number of instructions contained within this block
	 */
	public int getInstructionCount() {
		return instructionMap.size();
	}

	/**
	 * @return number of instructions which were added to the program
	 * successfully.
	 */
	public int getInstructionsAddedCount() {
		return instructionsAddedCount;
	}

	/**
	 * Set the number of instructions which were added to the program
	 * @param count
	 */
	public void setInstructionsAddedCount(int count) {
		this.instructionsAddedCount = count;
	}

	public Address getFlowFromAddress() {
		return flowFrom;
	}

	public void setFlowFromAddress(Address flowFrom) {
		this.flowFrom = flowFrom;
	}

	public boolean hasInstructionError() {
		return instructionError != null;
	}

}
