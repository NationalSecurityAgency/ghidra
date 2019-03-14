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
package ghidra.util.state.analysis;

import java.util.LinkedList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.state.*;
import ghidra.util.task.TaskMonitor;

public class MySwitchAnalyzer implements FunctionAnalyzer {
	
	private final Program program;
	private final AddressFactory addrFactory;
	private final Listing listing;
	private ReferenceManager refMgr;

	public MySwitchAnalyzer(Program program) {
		this.program = program;
		addrFactory = program.getAddressFactory();
		listing = program.getListing();
		refMgr = program.getReferenceManager();
	}

	public static ResultsState analyze(Program program, Address functionEntry, TaskMonitor monitor) throws CancelledException {
long t = System.currentTimeMillis();		
		MySwitchAnalyzer analyzer = new MySwitchAnalyzer(program);
		ResultsState s = new ResultsState(functionEntry, analyzer, program, true, monitor);
t = System.currentTimeMillis() - t;
System.out.println("Time to build ResultState = " + t + " msec.");
		return s;
	}
	
	private void addReference(PcodeOp flowOp, Address toAddr) {
		
		Address flowFrom = flowOp.getSeqnum().getTarget();
		Instruction fromInstr = listing.getInstructionAt(flowFrom);
		
		for (Reference ref : fromInstr.getReferencesFrom()) {
			if (toAddr.equals(ref.getToAddress())) {
				return;
			}
		}
		
		FlowType ftype = fromInstr.getFlowType();
		
		fromInstr.addMnemonicReference(toAddr, ftype, SourceType.ANALYSIS);
	}

	public boolean resolvedFlow(PcodeOp op, Object opIndex, Address destAddr,
			ContextState currentState, ResultsState results, TaskMonitor monitor) {
		addReference(op, destAddr);
		return true;
	}
	
	public List<Address> unresolvedIndirectFlow(PcodeOp op, Object opIndex, Varnode destination,
			ContextState currentState, ResultsState results, TaskMonitor monitor) {
		
		if (destination instanceof VarnodeOperation) {
			VarnodeOperation dest = (VarnodeOperation)destination;
			return handleOffsetSwitchOperation(op, dest, currentState, results, monitor);
		}
		
//		Address blockEntryPoint = currentState.getEntryPoint().getTarget();
//		Address fallFrom = listing.getInstructionAt(blockEntryPoint).getFallFrom();
//		
//		Set<SequenceNumber> flowFroms = currentState.getFlowFroms();
		
		
		
		
		
		
		// TODO Auto-generated method stub
		return null;
	}
	
	private Address getAddress(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	/**
	 * 
	 * @param op
	 * @param dest
	 * @param currentState
	 * @param monitor
	 * @return
	 */
	private List<Address> handleOffsetSwitchOperation(PcodeOp op, VarnodeOperation destAddOp,
			ContextState currentState, ResultsState results, TaskMonitor monitor) {
		
//		Varnode baseOffset;
//		VarnodeOperation offsetExpr;
//		Varnode[] inputs = destAddOp.getInputValues();
//		if (!inputs[0].isConstant()) {
//			if (!inputs[1].isConstant() || !(inputs[0] instanceof VarnodeOperation)) {
//				return null;
//			}
//			baseOffset = inputs[1];
//			offsetExpr = (VarnodeOperation)inputs[0];
//		}
//		else if (inputs[1] instanceof VarnodeOperation) {
//			baseOffset = inputs[0];
//			offsetExpr = (VarnodeOperation)inputs[1];
//		}
//		else {
//			return null;
//		}
//		
//		Address tableBaseAddr = getAddress(baseOffset.getOffset());
//		Err.debug(this, "Switch base offset: " + tableBaseAddr);
//		
//		if (offsetExpr.getPCodeOp().getOpcode() == PcodeOp.INT_SEXT) {
//			
//		}
//		
//		Register indexReg = null;
//		try {
//			indexReg = findSingleRegister(offsetExpr);
//		} catch (MultipleRegInputsException e) {
//			return null;
//		}
//		if (indexReg == null) {
//			return null;
//		}
//		Err.debug(this, "Switch index register: " + indexReg);
		
		Msg.debug(this, "State-entry: " + currentState.getEntryPoint());
		
		for (SequenceNumber seq : currentState.getFlowFroms()) {
			Msg.debug(this, "State-flowFrom: " + seq);
		}
//		
//// TODO: Disable for performance benchmark	
//if (true) return null;		
//		
		
		
		Switch s = Switch.getIndirectJumpSwitch(program, destAddOp);
		if (s == null) {
			Msg.debug(this, "Unsupported indirect call at: " + op.getSeqnum().getTarget());
			return null;
		}
		
		Msg.debug(this, "Processing switch at: " + op.getSeqnum().getTarget());
		Msg.debug(this, "Switch class: " + s.getClass().getName());
		
		Varnode indexValue = s.getIndexValue();
		Varnode indexValueVarnode = indexValue;	// index value storage container
		SequenceNumber indexValueAssignedAt = null;
		Msg.debug(this, "Switch index expression: " + indexValue);
		if (indexValue instanceof VarnodeOperation) {
			
			// Index value is computed

// NOTE: Value may be constrained by its computation - can we bound expression to a value range ?
			
			VarnodeOperation indexValueOp = (VarnodeOperation)indexValue;
			// I expect that the indexValueVarnode should always be a register in this case
			// since it will be used in subsequent computations and switch guard(s)
			indexValueVarnode = indexValueOp.getPCodeOp().getOutput();
			Msg.debug(this, "Switch index variable: " + indexValueVarnode);
			indexValueAssignedAt = indexValueOp.getPCodeOp().getSeqnum();
			Msg.debug(this, "Switch index variable assigned at: " + indexValueAssignedAt);
			
		}
		else {
			

			Msg.debug(this, "Switch index is input parameter!");
			
			// TODO: How should we identify switch guard ??
			
		}
			
		// Rewind state - obtain state prior to index value assignment instruction and build flowList leading to switch
		LinkedList<SequenceNumber> flowList = new LinkedList<SequenceNumber>();
		flowList.addFirst(currentState.getEntryPoint());
		ContextState state = currentState;
		boolean stopRewind = false;
		while (state != null && !stopRewind) {
			flowList.addFirst(state.getEntryPoint());
			stopRewind = ( indexValueAssignedAt != null && state.getSequenceRange().contains(indexValueAssignedAt) );
			state = state.getPreviousContextState();
		}	
		if (state == null) {
			// Create function entry state
			state = new ContextState(results.getEntryPoint().getTarget(), program);
		}
		Msg.debug(this, "Rewind state to: " + state.getEntryPoint());
		
/// Objects instantiated below are specific to a single test case (i.e., testIndexValue)
		
//		int testIndexValue = 0;
		
		// Establish ResultsState for evaluating test case
// TODO:
//		ResultsState testState = new ResultsState(flowList, null, state, true, monitor);
//		testState.forcePcodeResult(indexValueAssignedAt, new Varnode(addrFactory.getConstantAddress(testIndexValue), indexValue.getSize()));
//		testState.setFlowInterruptAt(op.getSeqnum());
		

			
		
		
		
		
		// TODO: Examine changing ResultsState to work maintain instruction results instead of block results ??
		
		
		
		

//		try {
//			Err.debug(this, "Case 0: " + s.getCaseAddress(0));
//			Err.debug(this, "Case 1: " + s.getCaseAddress(1));
//			
//			
//		} catch (MemoryAccessException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (AddressOutOfBoundsException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		
		
		
		
		
		return null;
	}
	
	private static class MultipleRegInputsException extends RuntimeException {
	}

	private Register findSingleRegister(Varnode value) {
		if (value instanceof VarnodeOperation) {
			Register reg = null;
			for (Varnode input : ((VarnodeOperation)value).getInputValues()) {
				Register inputReg = findSingleRegister(input);
				if (inputReg != null) {
					if (reg != null && !reg.equals(inputReg)) {
						throw new MultipleRegInputsException();
					}
					reg = inputReg;
				}
			}
			return reg;
		}
		if (value.isAddress() || value.isRegister()) {
			return program.getRegister(value.getAddress(), value.getSize());
		}
		return null;
	}

	public void dataReference(PcodeOp op, int instrOpIndex,
			Varnode storageVarnode, RefType refType, TaskMonitor monitor)
			throws CancelledException {
		// TODO Auto-generated method stub
		
	}

	public void indirectDataReference(PcodeOp op, int instrOpIndex,
			Varnode offsetVarnode, int size, int storageSpaceID,
			RefType refType, TaskMonitor monitor) throws CancelledException {
		// TODO Auto-generated method stub
		
	}

	public boolean resolvedFlow(PcodeOp op, int instrOpIndex, Address destAddr,
			ContextState currentState, ResultsState results, TaskMonitor monitor)
			throws CancelledException {
		// TODO Auto-generated method stub
		return false;
	}

	public void stackReference(PcodeOp op, int instrOpIndex, int stackOffset,
			int size, int storageSpaceID, RefType refType, TaskMonitor monitor)
			throws CancelledException {
		// TODO Auto-generated method stub
		
	}

	public void stackReference(PcodeOp op, int instrOpIndex,
			VarnodeOperation computedStackOffset, int size, int storageSpaceID,
			RefType refType, TaskMonitor monitor) throws CancelledException {
		// TODO Auto-generated method stub
		
	}

	public List<Address> unresolvedIndirectFlow(PcodeOp op, int instrOpIndex,
			Varnode destination, ContextState currentState,
			ResultsState results, TaskMonitor monitor)
			throws CancelledException {
		// TODO Auto-generated method stub
		return null;
	}


	

}
