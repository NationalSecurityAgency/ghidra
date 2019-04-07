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
package ghidra.program.model.block;

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * FollowFlow follows the program's code flow either forward or backward from an initial
 * address set. It adds the flow addresses to the initial address set by flowing "from" the 
 * initial addresses in the forward direction or by flowing "to" the initial addresses when
 * used in the backward direction.
 * The flow can be limited by indicating the flow types (i.e. unconditional call, 
 * computed jump, etc.) that we do NOT want to follow.
 */
public class FollowFlow {
	private Program program;
	private AddressSet initialAddresses;

	private boolean followAllFlow = true;
	private boolean followComputedCall = true;
	private boolean followConditionalCall = true;
	private boolean followUnconditionalCall = true;
	private boolean followComputedJump = true;
	private boolean followConditionalJump = true;
	private boolean followUnconditionalJump = true;
	private boolean followPointers = true;

	private boolean followIntoFunction = true;
	private Address nextSymbolAddr;

	/**
	 * Constructor
	 *
	 * @param program the program whose flow we are following.
	 * @param addressSet the initial addresses that should be flowed from or flowed to.
	 * @param doNotFollow array of flow types that are not to be followed.
	 * null or empty array indicates follow all flows. The following are valid
	 * flow types for the doNotFollow array:
	 * <BR>FlowType.COMPUTED_CALL
	 * <BR>FlowType.CONDITIONAL_CALL
	 * <BR>FlowType.UNCONDITIONAL_CALL
	 * <BR>FlowType.COMPUTED_JUMP
	 * <BR>FlowType.CONDITIONAL_JUMP
	 * <BR>FlowType.UNCONDITIONAL_JUMP
	 * <BR>FlowType.INDIRECTION
	 */
	public FollowFlow(Program program, AddressSet addressSet, FlowType[] doNotFollow) {
		this.program = program;
		this.initialAddresses = addressSet;
		updateFollowFlags(doNotFollow);
	}

	/**
	 * Constructor
	 * 
	 * @param program the program whose flow we are following.
	 * @param addressSet the initial addresses that should be flowed from or flowed to.
	 * @param doNotFollow array of flow types that are not to be followed.
	 * null or empty array indicates follow all flows. The following are valid
	 * flow types for the doNotFollow array:
	 * <BR>FlowType.COMPUTED_CALL
	 * <BR>FlowType.CONDITIONAL_CALL
	 * <BR>FlowType.UNCONDITIONAL_CALL
	 * <BR>FlowType.COMPUTED_JUMP
	 * <BR>FlowType.CONDITIONAL_JUMP
	 * <BR>FlowType.UNCONDITIONAL_JUMP
	 * <BR>FlowType.INDIRECTION
	 * @param followIntoFunctions true if flows into (or back from) defined functions
	 * should be followed.
	 */
	public FollowFlow(Program program, AddressSet addressSet, FlowType[] doNotFollow,
			boolean followIntoFunctions) {
		this(program, addressSet, doNotFollow);
		this.followIntoFunction = followIntoFunctions;
	}

	/**
	 * updateFollowFlags
	 *
	 * @param doNotFollow array of flow types that are not to be followed.
	 * null or empty array indicates follow all flows.
	 */
	private void updateFollowFlags(FlowType[] doNotFollow) {
		if ((doNotFollow != null) && (doNotFollow.length > 0)) {
			followAllFlow = false;
			for (int index = 0; index < doNotFollow.length; index++) {
				if (doNotFollow[index].equals(RefType.COMPUTED_CALL)) {
					followComputedCall = false;
				}
				else if (doNotFollow[index].equals(RefType.CONDITIONAL_CALL)) {
					followConditionalCall = false;
				}
				else if (doNotFollow[index].equals(RefType.UNCONDITIONAL_CALL)) {
					followUnconditionalCall = false;
				}
				else if (doNotFollow[index].equals(RefType.COMPUTED_JUMP)) {
					followComputedJump = false;
				}
				else if (doNotFollow[index].equals(RefType.CONDITIONAL_JUMP)) {
					followConditionalJump = false;
				}
				else if (doNotFollow[index].equals(RefType.UNCONDITIONAL_JUMP)) {
					followUnconditionalJump = false;
				}
				else if (doNotFollow[index].equals(RefType.INDIRECTION)) {
					followPointers = false;
				}
			}
		}
	}

	/**
	 * getAddressFlow follows the program's code flow and creates an address
	 * set for the flow from the addresses that are provided when flowing in the forward direction
	 * or creates an address set for the flows to the addresses in the address set if flowing
	 * in the backward direction.
	 * @param monitor a cancellable task monitor, may be null
	 * @param startAddresses the initial addresses that should be flowed from or flowed to.
	 * @param forward true to determine the flows "from" the startAddresses. false (backward) to 
	 * determine flows "to" the startAddresses.
	 */
	private AddressSet getAddressFlow(TaskMonitor monitor, AddressSet startAddresses,
			boolean forward) {

		if (monitor == null) {
			monitor = TaskMonitorAdapter.DUMMY_MONITOR; // create dummy monitor
		}

		// Create a new address set to hold the entire flow.
		AddressSet addressSet = new AddressSet();
		AddressSet coveredAddrs = new AddressSet();

		// If we don't have any addresses simply return.
		if (startAddresses == null || startAddresses.getNumAddresses() <= 0) {
			return addressSet;
		}

		// Iterate over all code units whose minimum address is contained within startAddresses
		Listing listing = program.getListing();
		CodeUnitIterator cuIter = listing.getCodeUnits(startAddresses, true);
		while (!monitor.isCancelled() && cuIter.hasNext()) {
			CodeUnit codeUnit = cuIter.next();
			coveredAddrs.addRange(codeUnit.getMinAddress(), codeUnit.getMaxAddress());
			getCodeUnitFlow(monitor, startAddresses, addressSet, codeUnit, forward);
		}

		// Make sure we did not omit any data elements
		AddressSet addrs = new AddressSet(startAddresses);
		addrs.delete(coveredAddrs);
		AddressIterator addrIter = addrs.getAddresses(true);
		while (!monitor.isCancelled() && addrIter.hasNext()) {
			Address addr = addrIter.next();
			if (addressSet.contains(addr))
				continue;
			Data data = listing.getDefinedDataContaining(addr);
			if (forward) {
				followCode(monitor, addressSet, data, addr);
			}
			else {
				followCodeBack(monitor, addressSet, data, addr);
			}
		}

		if (monitor.isCancelled()) {
			return new AddressSet();  // don't return a partial result
		}
		return addressSet;

	} // flowAddresses

	/**
	 * Add into the flowAddressSet those addresses we flow to from the specified codeUnit when 
	 * flowing forward or the addresses that flow to the code unit when determining flows in the 
	 * backward direction.
	 * For data, ensure that those primitive data elements followed are contained within the 
	 * startAddresses.
	 * @param monitor a cancellable task monitor
	 * @param startAddresses the addresses from which flow may start.
	 * @param flowAddressSet the collection of addresses encountered within the flow.
	 * @param codeUnit the instruction or data code unit to start from.
	 * @param forward true to determine the flows from the code unit. false to determine flows
	 * to the code unit.
	 */
	private void getCodeUnitFlow(TaskMonitor monitor, AddressSet startAddresses,
			AddressSet flowAddressSet, CodeUnit codeUnit, boolean forward) {
		if (codeUnit instanceof Data) {
			getIndirectCodeFlow(monitor, startAddresses, flowAddressSet, (Data) codeUnit, forward);
		}
		else if (codeUnit instanceof Instruction) {
			getInstructionFlow(monitor, flowAddressSet, (Instruction) codeUnit, forward);
		}
	}

	private void getInstructionFlow(TaskMonitor monitor, AddressSet flowAddressSet,
			Instruction instruction, boolean forward) {
		// Follow instruction
		if (forward) {
			// Flow from the instruction
			followCode(monitor, flowAddressSet, instruction, null);
		}
		else {
			// Flow to the instruction
			followCodeBack(monitor, flowAddressSet, instruction, null);
		}
	}

	private void getIndirectCodeFlow(TaskMonitor monitor, AddressSet startAddresses,
			AddressSet flowAddressSet, Data data, boolean forward) {
		// Follow data - isolate each primitive within startAddresses
		if (!data.isDefined()) {
			return;
		}
		Address maxAddr = data.getMaxAddress();
		AddressIterator addrIter = startAddresses.getAddresses(data.getMinAddress(), true);

		while (!monitor.isCancelled() && addrIter.hasNext()) {
			Address addr = addrIter.next();
			if (addr.compareTo(maxAddr) > 0)
				break;

			if (flowAddressSet.contains(addr))
				continue;

			if (forward) {
				followCode(monitor, flowAddressSet, data, addr);
			}
			else {
				followCodeBack(monitor, flowAddressSet, data, addr);
			}
		}
	}

	/**
	 * followCode follows the program's code unit (instruction or data) flow and
	 * adds addresses to the address set for the flow from the current location.
	 * The plugin's properties indicate which flow types should be followed for
	 * instruction code units.
	 * @param monitor a cancellable task monitor
	 * @param flowAddressSet the address set to be added to
	 * @param currentCodeUnit the code unit to flow from.
	 *     Appropriate flows out of this code unit will be traversed.
	 * @param dataAddr null or the address to flow from within the currentCodeUnit for Data.
	 */
	private void followCode(TaskMonitor monitor, AddressSet flowAddressSet, CodeUnit codeUnit,
			Address dataAddr) {

		if (codeUnit == null) {
			return;
		}
		Stack<CodeUnit> instructionStack = new Stack<CodeUnit>();
		if (codeUnit instanceof Data) {
			followData(instructionStack, flowAddressSet, (Data) codeUnit, dataAddr);
		}
		else {
			instructionStack.push(codeUnit);
		}
		Address start_addr = codeUnit.getMinAddress();

		if (!followIntoFunction) {
			try {
				nextSymbolAddr = getNextSymbolAddress(start_addr.add(1), nextSymbolAddr);
			} catch (AddressOutOfBoundsException e) {
				nextSymbolAddr = null;
			}
		}

		while (!monitor.isCancelled() && !instructionStack.isEmpty()) {

			codeUnit = instructionStack.pop();
			if (!(codeUnit instanceof Instruction)) {
				// Probably undefined data which should be disassembled
				flowAddressSet.addRange(codeUnit.getMinAddress(), codeUnit.getMaxAddress());
				continue;
			}

			Instruction currentInstr = (Instruction) codeUnit;
			Address currentAddress = currentInstr.getMinAddress();

			// Return if code unit already encountered
			if (flowAddressSet.contains(currentAddress)) {
				continue;
			}

			// If code unit is a delay-slot instruction, backup to delayed instruction     	
			Instruction instr = currentInstr;
//        	while (instr.isInDelaySlot()) {      		
//        		Address fallFrom = instr.getFallFrom();
//        		if (fallFrom == null) {
//        			// assumes delay slot instructions have no flow
//        			flowAddressSet.addRange(instr.getMinAddress(),
//                                    currentInstr.getMaxAddress());
//  					break;
//        		}
//        		instr = program.getListing().getInstructionContaining(fallFrom);	
//        	}
//        	if (instr.isInDelaySlot())
//        		continue;  // unable to find non-delay-slot instruction
//			currentInstr = instr;

			// handle instruction - include associated delay slot instructions
			Address end = instr.getMaxAddress();
			int delaySlotDepth = instr.getDelaySlotDepth();
			for (int i = 0; i < delaySlotDepth; i++) {
				instr = instr.getNext();
				if (instr == null)
					break;
				end = instr.getMaxAddress();
			}
			flowAddressSet.addRange(currentInstr.getMinAddress(), end);
			followInstruction(instructionStack, flowAddressSet, currentInstr);

		}
	} // followCode

	/**
	 * followCodeBack follows the program's code unit (instruction or data) flow backwards and
	 * adds addresses to the address set for the flow to the indicated code unit.
	 * The plugin's properties indicate which flow types should be followed for
	 * code units.
	 * @param monitor a cancellable task monitor
	 * @param flowAddressSet the address set to be added to
	 * @param codeUnit the code unit to flow to ( or flow back from).
	 *        Appropriate flows into this code unit will be traversed.
	 * @param dataAddress the data address if we are trying to follow a flow to data, or
	 *        null if flowing to an instruction.
	 */
	private void followCodeBack(TaskMonitor monitor, AddressSet flowAddressSet, CodeUnit codeUnit,
			Address dataAddress) {

		if (codeUnit == null) {
			return;
		}
		Stack<CodeUnit> codeUnitStack = new Stack<CodeUnit>(); // additional code to be processed.
		if (codeUnit instanceof Data) {
			followDataBack(codeUnitStack, flowAddressSet, (Data) codeUnit, dataAddress);
			// Make sure we don't lose the data address from the original selection,
			// if followDataBack didn't put a pointer in the flow.
			if (dataAddress != null && !flowAddressSet.contains(dataAddress)) {
				flowAddressSet.add(dataAddress);
			}
		}
		else {
			codeUnitStack.push(codeUnit);
		}

		while (!monitor.isCancelled() && !codeUnitStack.isEmpty()) {
			codeUnit = codeUnitStack.pop();
			if (codeUnit instanceof Instruction) {
				// getAdjustedInstruction() will add the instruction and any delay slots to the 
				// flowAddressSet and then return the instruction to flow backwards from.
				Instruction currentInstr =
					getAdjustedInstruction((Instruction) codeUnit, flowAddressSet);
				if (currentInstr != null) {
					followInstructionBack(codeUnitStack, flowAddressSet, currentInstr);
				}
			}
			else if (codeUnit instanceof Data) {
				followDataBack(codeUnitStack, flowAddressSet, (Data) codeUnit, dataAddress);
			}
		}
	} // followCodeBack

	/**
	 * Gets the instruction to be processed, which has been adjusted to the first instruction when 
	 * the one passed in is part of a delay slot. If this isn't part of a delay slot then the 
	 * original instruction is returned.<BR>
	 * For a delay slot, all the instructions for the delay slot will be added to the flowAddressSet. 
	 * Otherwise the original instruction is added to the flowAddressSet.
	 * @param currentInstr the instruction to possibly adjust
	 * @param flowAddressSet the address set to hold the entire flow.
	 * @return the original instruction or the first instruction that is part of a delay slot.
	 */
	private Instruction getAdjustedInstruction(Instruction currentInstr, AddressSet flowAddressSet) {
		Address currentAddress = currentInstr.getMinAddress();

		// Return if code unit already encountered
		if (flowAddressSet.contains(currentAddress)) {
			return null;
		}

		// If code unit is a delay-slot instruction, backup to delayed instruction     	
		Instruction instr = currentInstr;
		while (instr.isInDelaySlot()) {
			Address fallFrom = instr.getFallFrom();
			if (fallFrom == null) {
				// assumes delay slot instructions have no flow
				flowAddressSet.addRange(instr.getMinAddress(), currentInstr.getMaxAddress());
				break;
			}
			instr = program.getListing().getInstructionContaining(fallFrom);
		}

		currentInstr = instr;

		// handle instruction - include associated delay slot instructions
		Address end = instr.getMaxAddress();
		for (int i = instr.getDelaySlotDepth(); i > 0; i--) {
			instr = instr.getNext();
			if (instr == null)
				break;
			end = instr.getMaxAddress();
		}
		flowAddressSet.addRange(currentInstr.getMinAddress(), end);

		return currentInstr;
	}

	private Address getNextSymbolAddress(Address curAddr, Address curNext) {
		if (curAddr == null) {
			return null;
		}
		// once there is no next function, don't return one.
		if (curNext == Address.NO_ADDRESS) {
			return curNext;
		}

		if (curNext == null || curNext.compareTo(curAddr) < 0) {
			// find the next function symbol from curAddr to end of current space
			SymbolTable symbolTable = program.getSymbolTable();
			Memory memory = program.getMemory();
			SymbolIterator symbols = symbolTable.getSymbolIterator(curAddr, true);
			if (symbols.hasNext()) {
				Symbol symbol = symbols.next();
				Address addr = symbol.getAddress();
				if (addr.getAddressSpace().equals(curAddr.getAddressSpace()) && memory.contains(addr)) {
					return addr;
				}
			}
			return Address.NO_ADDRESS;
		}
		return curNext;
	}

	/**
	 * followInstruction follows the program's instruction flow and adds addresses
	 * to the address set for the flow from the current location.
	 * The plugin's properties indicate which flow types should be followed for
	 * instruction code units.
	 *
	 * @param flowAddressSet the address set to add our addresses to.
	 * @param currentCodeUnit the Instruction object to flow from.
	 *     Appropriate flows out of this code unit will be traversed.
	 */
	private void followInstruction(Stack<CodeUnit> instructionStack, AddressSet flowAddressSet,
			Instruction currentInstr) {

		Address nextAddress = null;

		/*****************
		 * Follow Flows  *
		 *****************/
		Address[] flowAddresses = getFlowsFromInstruction(currentInstr);
		for (int index = 0; (flowAddresses != null) && (index < flowAddresses.length); index++) {
			nextAddress = flowAddresses[index];
			if (nextAddress != null) {
				CodeUnit nextCodeUnit = program.getListing().getCodeUnitContaining(nextAddress);
				if (nextCodeUnit != null) {
					if (nextCodeUnit instanceof Data) {
						followData(instructionStack, flowAddressSet, (Data) nextCodeUnit,
							nextAddress);
					}
					else {
						instructionStack.push(nextCodeUnit);
					}
				}
			}
		}

		/***********************
		 * Follow Fallthrough  *
		 ***********************/
		// If we can fall through then get that instruction, add it to the
		// address set and see where it flows.
		nextAddress = currentInstr.getFallThrough();

		// Don't follow if not following into functions, and fall into a function.
		if (!followIntoFunction) {
			nextSymbolAddr = getNextSymbolAddress(nextAddress, nextSymbolAddr);
			if (nextSymbolAddr != null && nextSymbolAddr.equals(nextAddress)) {
				Symbol symbol = program.getSymbolTable().getPrimarySymbol(nextAddress);
				if (symbol.getSymbolType() == SymbolType.FUNCTION) {
					nextAddress = null;
				}
			}
		}

		if (nextAddress != null) {
			Instruction nextInstruction = program.getListing().getInstructionAt(nextAddress);
			if (nextInstruction != null) {
				instructionStack.push(nextInstruction);
			}
		}

	}

	/**
	 * followInstructionBack follows the program's instruction flow and adds addresses
	 * to the address set for the flow to the current instruction.
	 * The plugin's properties indicate which flow types should be followed for
	 * instruction code units.
	 *
	 * @param instructionStack the instruction stack of instructions to flow to.
	 * @param flowAddressSet the address set to add our addresses to.
	 * @param currentInstr the Instruction object to flow to.
	 *     Appropriate flows to this code unit will be traversed.
	 */
	private void followInstructionBack(Stack<CodeUnit> instructionStack, AddressSet flowAddressSet,
			Instruction currentInstr) {

		// Don't follow if not following into (or back from) functions, and instruction is at a function.
		if (!followIntoFunction) {
			Symbol primarySymbol = currentInstr.getPrimarySymbol();
			if (primarySymbol.getSymbolType() == SymbolType.FUNCTION) {
				return;
			}
		}

		Address fromAddress = null; // The from address

		/*************************
		 * Follow Flows Backward *
		 *************************/
		Address[] flowFromAddresses = getFlowsAndPointersToInstruction(currentInstr);
		for (int index = 0; (flowFromAddresses != null) && (index < flowFromAddresses.length); index++) {
			fromAddress = flowFromAddresses[index];
			if (fromAddress != null) {
				CodeUnit nextCodeUnit = program.getListing().getCodeUnitContaining(fromAddress);
				if (nextCodeUnit != null) {
					if (nextCodeUnit instanceof Data) {
						Data data = (Data) nextCodeUnit;
						Address minAddress = data.getMinAddress();
						int offset = (int) fromAddress.subtract(minAddress);
						Data primitive = data.getPrimitiveAt(offset);
						if ((primitive != null) && primitive.isPointer()) {
							// If we flowed from an instruction back to a pointer then see if
							// we should continue to flow back further from that data.
							followDataBack(instructionStack, flowAddressSet, (Data) nextCodeUnit,
								fromAddress);
						}
					}
					else {
						instructionStack.push(nextCodeUnit);
					}
				}
			}
		}

		// fallFrom will get flows to beginning of delay slot instructions,
		// but need to catch any flows directly into delay slot instructions.
		getFlowsToPreceedingDelaySlots(currentInstr, instructionStack, flowAddressSet);

		/*********************
		 * Follow Fall From  *
		 *********************/
		// If we can fall through to here then get that instruction that fell through, add it to the
		// code unit stack so we can see if we can flow to it.
		fromAddress = currentInstr.getFallFrom(); // the address we fell from.

		if (fromAddress != null) {
			Instruction fromInstruction = program.getListing().getInstructionAt(fromAddress);
			if (fromInstruction != null) {
				instructionStack.push(fromInstruction);
			}
		}
	}

	private void getFlowsToPreceedingDelaySlots(Instruction currentInstruction,
			Stack<CodeUnit> codeUnitStack, AddressSet flowAddressSet) {

		Instruction instruction = currentInstruction;
		boolean inDelaySlot = false;
		List<Instruction> list = new ArrayList<Instruction>();
		int alignment = program.getLanguage().getInstructionAlignment();
		if (alignment < 1) {
			alignment = 1;
		}
		Listing listing = program.getListing();
		do {
			// check each delay slot instruction for flows into it.
			try {
				instruction =
					listing.getInstructionContaining(instruction.getMinAddress().subtractNoWrap(
						alignment));
				if (instruction == null) {
					break;
				}
				inDelaySlot = instruction.isInDelaySlot();
				if (inDelaySlot) {
					handleFlowsIntoDelaySlot(instruction, codeUnitStack, flowAddressSet, list,
						listing);
				}
			}
			catch (AddressOverflowException e) {
				return;
			}
		}
		while (inDelaySlot);
	}

	private void handleFlowsIntoDelaySlot(Instruction instruction, Stack<CodeUnit> codeUnitStack,
			AddressSet flowAddressSet, List<Instruction> delaySlotList, Listing listing) {

		delaySlotList.add(instruction); // Hold on to instruction until one has a ref.

		boolean foundFlowToDelaySlot = false;
		Address[] flowFromAddresses = getFlowsAndPointersToInstruction(instruction);
		for (Address fromAddress : flowFromAddresses) {
			CodeUnit codeUnit = listing.getCodeUnitAt(fromAddress);
			if (codeUnit != null) {
				codeUnitStack.add(codeUnit);
				foundFlowToDelaySlot = true;
			}
		}
		if (foundFlowToDelaySlot) {
			// Save the delay slot instructions as part of the flow.
			for (Instruction delaySlotInstruction : delaySlotList) {
				flowAddressSet.add(delaySlotInstruction.getMinAddress(),
					delaySlotInstruction.getMaxAddress());
			}
			delaySlotList.clear();
		}
	}

	/**
	 * Determines whether the indicated flow type is one that is currently 
	 * supposed to be followed.
	 * 
	 * @param currentFlowType the flow type to check
	 * @return boolean true if this flow type should be followed.
	 */
	private boolean shouldFollowFlow(FlowType currentFlowType) {
		boolean shouldFollowFlow = true;
		// Determine whether or not to follow this particular flow.
		if ((!followAllFlow) &&
			((currentFlowType.equals(RefType.COMPUTED_CALL) && !followComputedCall) ||
				(currentFlowType.equals(RefType.COMPUTED_JUMP) && !followComputedJump) ||
				(currentFlowType.equals(RefType.CONDITIONAL_JUMP) && !followConditionalJump) ||
				(currentFlowType.equals(RefType.UNCONDITIONAL_JUMP) && !followUnconditionalJump) ||
				(currentFlowType.equals(RefType.CONDITIONAL_CALL) && !followConditionalCall) ||
				(currentFlowType.equals(RefType.UNCONDITIONAL_CALL) && !followUnconditionalCall) || (currentFlowType.equals(RefType.INDIRECTION) && !followPointers))) {
			shouldFollowFlow = false;
		}
		else {
			shouldFollowFlow = true;
		}
		return shouldFollowFlow;
	}

	/**
	 * Gets the addresses of where this instruction flows. Only flow types
	 * matching the ones that should be followed will have the address it flows
	 * to returned.
	 * 
	 * @param the instruction being flowed from.
	 * @return array of the addresses being flowed to in the manner we are
	 * interested in.
	 */
	private Address[] getFlowsFromInstruction(Instruction instr) {
		Reference[] refsFrom = instr.getReferencesFrom();
		int length = refsFrom.length;
		List<Address> list = new ArrayList<Address>(length);
		for (int i = 0; i < length; i++) {
			RefType refType = refsFrom[i].getReferenceType();
			if (refType.isFlow()) {
				if (shouldFollowFlow((FlowType) refType)) {
					Address toAddr = refsFrom[i].getToAddress();
					if (!followIntoFunction) {
						SymbolTable symbolTable = program.getSymbolTable();
						Symbol primarySymbol = symbolTable.getPrimarySymbol(toAddr);
						if (primarySymbol.getSymbolType() == SymbolType.FUNCTION) {
							continue;
						}
					}
					list.add(toAddr);
				}
			}
		}
		return list.toArray(new Address[list.size()]);
	}

	/**
	 * Gets the addresses that flow to this instruction. Only flow types
	 * matching the ones that should be followed will have the address it flows
	 * from returned.
	 * 
	 * @param the instruction being flowed to.
	 * @return array of the addresses that flow to the instruction in the manner we are
	 * interested in.
	 */
	private Address[] getFlowsAndPointersToInstruction(Instruction instr) {
		if (!followIntoFunction) {
			SymbolTable symbolTable = program.getSymbolTable();
			Symbol primarySymbol = symbolTable.getPrimarySymbol(instr.getMinAddress());
			if (primarySymbol != null && primarySymbol.getSymbolType() == SymbolType.FUNCTION) {
				// Not following into functions and we are at a function, so don't follow back.
				return new Address[0];
			}
		}

		Listing listing = program.getListing();
		ArrayList<Address> list = new ArrayList<Address>();
		ReferenceIterator referenceIteratorTo = instr.getReferenceIteratorTo();
		for (Reference reference : referenceIteratorTo) {
			RefType refType = reference.getReferenceType();
			if (followPointers && refType.isData()) {
				Address fromAddress = reference.getFromAddress();
				Data data = listing.getDataContaining(fromAddress);
				if (data == null) {
					continue;
				}
				Address minAddress = data.getMinAddress();
				int offset = (int) fromAddress.subtract(minAddress);
				Data primitive = data.getPrimitiveAt(offset);
				if ((primitive != null) && primitive.isPointer()) {
					// Add just address of the pointer?
					list.add(fromAddress);
				}
			}
			else if (refType.isFlow()) {
				if (shouldFollowFlow((FlowType) refType)) {
					Address fromAddress = reference.getFromAddress();
					list.add(fromAddress);
				}
			}
		}
		return list.toArray(new Address[list.size()]);
	}

	/**
	 * followData follows the program's code flow and adds addresses to the address set for the 
	 * flow from the current data item if it has a pointer at the specified address with a 
	 * reference to an instruction. If the flow at the address isn't from a pointer to 
	 * an instruction then just the address passed to this method is added to the flow set.
	 *
	 * @param flowAddressSet the address set to add our addresses to.
	 * @param currentCodeUnit the Data object to flow from.
	 *     Appropriate flows out of this code unit will be traversed.
	 * @param addr the flow reference address which is contained within data.
	 */
	private void followData(Stack<CodeUnit> instructionStack, AddressSet flowAddressSet, Data data,
			Address addr) {

		if (flowAddressSet.contains(addr))
			return; // Already processed this address.

		Address min = addr;
		Address max = min;
		int offset = (int) addr.subtract(data.getMinAddress());
		Data primitive = data.getPrimitiveAt(offset);
		if (primitive != null) {
			max = primitive.getMaxAddress();
			// Follow pointers if enabled
			if (followPointers && primitive.isPointer()) {
				// If the pointer has a user reference of type Data then
				// follow the reference . Otherwise use the data value.
				ReferenceManager referenceManager = program.getReferenceManager();
				Reference[] memRefs = referenceManager.getReferencesFrom(addr);
				boolean foundRef = false;
				for (int i = 0; i < memRefs.length; i++) {
					RefType rt = memRefs[i].getReferenceType();
					if (rt.isData()) {
						if (pushInstruction(instructionStack, memRefs[i].getToAddress())) {
							foundRef = true; // pointer was to an instruction.
						}
					}
				}
				if (!foundRef) {
					// Didn't have a data ref to an instruction so flow to the address indicated 
					// by the pointer's value if there is an instruction there.
					pushInstruction(instructionStack, (Address) primitive.getValue());
				}
			}
		}
		flowAddressSet.addRange(min, max); // Add the addresses for the pointer or Data minimum address.
	}

	/**
	 * followDataBack follows the program's code flow backwards and adds addresses to the
	 * address set for the flow to the current data item.
	 *
	 * @param instructionStack the instruction stack of instructions that flow to addr.
	 * @param flowAddressSet the address set to add our addresses to.
	 * @param data the Data object to flow to.
	 *     Appropriate flows into this data code unit will be traversed.
	 * @param addr the flow to reference address which is contained within the data code unit.
	 */
	private void followDataBack(Stack<CodeUnit> instructionStack, AddressSet flowAddressSet,
			Data data, Address addr) {

		if (flowAddressSet.contains(addr))
			return; // Already processed this address.

		// If there is a pointer at the address, then add the addresses where the pointer is.
		// Otherwise, the address will need to be added by the caller of this function.
		addPointerToFlow(flowAddressSet, data, addr);

		// If the Data code unit is flowed to by INDIRECTION from any instructions then put
		// those instructions on the stack for further processing as part of the flow to the 
		// Data address.
		ReferenceManager referenceManager = program.getReferenceManager();
		ReferenceIterator referenceIteratorTo = referenceManager.getReferencesTo(addr);
		for (Reference reference : referenceIteratorTo) {
			RefType refType = reference.getReferenceType();
			Address fromAddress = reference.getFromAddress();
			CodeUnit fromCodeUnit = program.getListing().getCodeUnitContaining(fromAddress);
			if (refType.equals(RefType.INDIRECTION) && (fromCodeUnit instanceof Instruction)) {
				// Put the instruction that flows to this data on the stack so we can 
				// continue flow back from it.
				instructionStack.add(fromCodeUnit);
			}
		}
	}

	/**
	 * If there is a pointer at the indicated address, this adds the addresses for the pointer
	 * into the address set of flows.
	 * @param flowAddressSet the address set containing the addresses that make up the flow so far.
	 * @param data a Data code unit containing the address to be processed.
	 * @param addr the address to be processed.
	 */
	private void addPointerToFlow(AddressSet flowAddressSet, Data data, Address addr) {
		int offset = (int) addr.subtract(data.getMinAddress());
		Data primitive = data.getPrimitiveAt(offset);
		if ((primitive != null) && primitive.isPointer()) {
			flowAddressSet.addRange(primitive.getMinAddress(), primitive.getMaxAddress());
		}
	}

	/**
	 * Push the instruction at the indicated address onto the flow stack. If the
	 * indicated address is not the min address of a code unit then do nothing.
	 * @param cuStack the code unit stack of flows to be followed
	 * @param addr the address of the code unit
	 */
	private boolean pushInstruction(Stack<CodeUnit> cuStack, Address addr) {
		if (addr == null) {
			return false;
		}
		CodeUnit codeUnit = program.getListing().getInstructionAt(addr);
		if (codeUnit != null) {
			cuStack.push(codeUnit);
			return true;
		}
		return false;
	}

	/** 
	 * Determines the address set that flows from the addresses in this FollowFlow object's
	 * initialAddresses set. The address set is determined by what addresses were provided 
	 * when the FollowFlow was constructed and the type of flow requested.
	 * This method follows flows in the forward direction.
	 * @param monitor a cancellable task monitor, may be null
	 * @return the resulting address set.
	 */
	public AddressSet getFlowAddressSet(TaskMonitor monitor) {
		return getAddressFlow(monitor, initialAddresses, true);
	}

	/** 
	 * Determines the address set that flows to the addresses in this FollowFlow object's
	 * initialAddresses set. The address set is determined by what addresses were provided 
	 * when the FollowFlow was constructed and the type of flow requested. The constructor
	 * indicated the flow types not to be followed. All others will be traversed in the
	 * backwards direction to determine the addresses that are flowing to those in the initial
	 * set.
	 * @param monitor a cancellable task monitor, may be null
	 * @return the resulting address set.
	 */
	public AddressSet getFlowToAddressSet(TaskMonitor monitor) {
		return getAddressFlow(monitor, initialAddresses, false);
	}

} // end FollowFlow class

