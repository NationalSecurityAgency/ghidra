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
// Build ResultState for current function
// @category Experimental

import java.util.*;

import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.state.*;
import ghidra.util.task.TaskMonitor;

@SuppressWarnings("all") // TODO remove this when we decide to support this script
public class BuildResultState extends GhidraScript {

	private final Set<VarnodeOperation> computedStackAccess = new HashSet<>();
	private final TreeMap<Address, Integer> stackElementSizes = new TreeMap<>();

	private Integer stackStorageSpaceId;

	@Override
	public void run() throws Exception {

		final Function func =
			currentProgram.getFunctionManager().getFunctionContaining(currentAddress);
		if (func == null) {
			Msg.showError(this, null, "BuildResultState Error",
				"Current location not contained within a function");
			return;
		}

		final Listing listing = currentProgram.getListing();
		final AddressFactory addrFactory = currentProgram.getAddressFactory();
		final ReferenceManager refMgr = currentProgram.getReferenceManager();

		ResultsState results = new ResultsState(func.getEntryPoint(), new FunctionAnalyzer() {

			private AddressSpace stackSpace = currentProgram.getAddressFactory().getStackSpace();

			@Override
			public void dataReference(PcodeOp op, int instrOpIndex, Varnode storageVarnode,
					RefType refType, TaskMonitor monitor) throws CancelledException {
				// TODO Auto-generated method stub
				Msg.info(this, "Data Ref: " + storageVarnode + " " + refType);
			}

			@Override
			public void indirectDataReference(PcodeOp op, int instrOpIndex, Varnode offsetVarnode,
					int size, int storageSpaceID, RefType refType, TaskMonitor monitor)
					throws CancelledException {
				// TODO Auto-generated method stub

			}

			@Override
			public boolean resolvedFlow(PcodeOp op, int instrOpIndex, Address destAddr,
					ContextState currentState, ResultsState results, TaskMonitor monitor)
					throws CancelledException {
				Address opAddr = op.getSeqnum().getTarget();
				Instruction instr = currentProgram.getListing().getInstructionAt(opAddr);
				boolean conditional = instr.getFlowType().isConditional();
				FlowType refType;
				switch (op.getOpcode()) {
					case PcodeOp.CALL:
						refType =
							conditional ? RefType.CONDITIONAL_CALL : RefType.UNCONDITIONAL_CALL;
						break;
					case PcodeOp.CALLIND:
						refType =
							conditional ? RefType.CONDITIONAL_COMPUTED_CALL : RefType.COMPUTED_CALL;
						break;
					case PcodeOp.BRANCH:
						refType =
							conditional ? RefType.CONDITIONAL_JUMP : RefType.UNCONDITIONAL_JUMP;
						break;
					case PcodeOp.BRANCHIND:
						refType =
							conditional ? RefType.CONDITIONAL_COMPUTED_JUMP : RefType.COMPUTED_JUMP;
						break;
					default:
						refType = RefType.FLOW;
				}
				instr.addOperandReference(instrOpIndex, destAddr, refType, SourceType.ANALYSIS);
				Msg.info(this, "Flow Ref: " + destAddr);
				return true;
			}

			@Override
			public void stackReference(PcodeOp op, int instrOpIndex, int stackOffset, int size,
					int storageSpaceID, RefType refType, TaskMonitor monitor)
					throws CancelledException {
				if (refType.isWrite()) {
					stackElementSizes.put(stackSpace.getAddress(stackOffset), size);
					stackStorageSpaceId = storageSpaceID;
				}
// TODO: don't add stack variables/references for now
				if (true) {
					return;
				}
				if (instrOpIndex < 0) {
					return;
				}
				Address fromAddr = op.getSeqnum().getTarget();
				Instruction instr = listing.getInstructionAt(fromAddr);
				if (instr == null) {
					return;
				}
				Address stackAddr = addrFactory.getStackSpace().getAddress(stackOffset);
				RefType rt = refType;
				Reference ref = refMgr.getReference(fromAddr, stackAddr, instrOpIndex);
				if (ref != null) {
					RefType existingRefType = ref.getReferenceType();
					if (existingRefType == rt) {
						return;
					}
					if (existingRefType == RefType.READ || existingRefType == RefType.WRITE) {
						rt = RefType.READ_WRITE;
					}
				}
				StackFrame stackFrame = func.getStackFrame();
				if (stackFrame.getVariableContaining(stackOffset) == null) {
					//long firstUseOffset = op.getSeqnum().getTarget().subtract(func.getEntryPoint());
					try {
						stackFrame.createVariable(null, stackOffset,
							Undefined.getUndefinedDataType(size), SourceType.ANALYSIS);
						// TODO: How can I tell when these stack variables are used as a pointer ?
					}
					catch (DuplicateNameException e) {
						throw new AssertException(); // unexpected
					}
					catch (InvalidInputException e) {
						Msg.error(this, "failed to create stack variable", e);
					}
				}
				refMgr.addStackReference(fromAddr, instrOpIndex, stackOffset, rt,
					SourceType.ANALYSIS);
			}

			@Override
			public void stackReference(PcodeOp op, int instrOpIndex,
					VarnodeOperation computedStackOffset, int size, int storageSpaceID,
					RefType refType, TaskMonitor monitor) throws CancelledException {
				if (refType.isWrite()) {
					computedStackAccess.add(computedStackOffset);
					stackStorageSpaceId = storageSpaceID;
				}
			}

			@Override
			public List<Address> unresolvedIndirectFlow(PcodeOp op, int instrOpIndex,
					Varnode destination, ContextState currentState, ResultsState results,
					TaskMonitor monitor) throws CancelledException {
				// TODO Auto-generated method stub
				return null;
			}

		}, currentProgram, true, monitor);

		// ResultsState results = MySwitchAnalyzer.analyze(currentProgram, func.getEntryPoint(), monitor);

		AddressSetView examinedSet = results.getExaminedSet();
		if (examinedSet != null) {
			PluginTool tool = state.getTool();
			if (tool != null) {
				tool.firePluginEvent(new ProgramSelectionPluginEvent("BuildResultState",
					new ProgramSelection(examinedSet), currentProgram));
			}
		}

		List<Register> regList = sort(results.getModifiedRegisters());

		System.out.println("Modified registers: " + regList);

		System.out.println("Preserved registers: " + sort(results.getPreservedRegisters()));

		System.out.println("Input registers: " + sort(results.getInputRegisters()));

		for (ResultsState.FramePointerCandidate candidate : results.getFramePointerCandidates()) {
			System.out.println("Frame-pointer candidate: " + candidate);
		}

		for (SequenceNumber seq : results.getReturnAddresses()) {
			int index = 0;
			Iterator<ContextState> contextStates = results.getContextStates(seq);
			while (contextStates.hasNext()) {
				dumpStackState(seq, ++index, contextStates.next());
			}
		}

//		for (SequenceNumber seq : results.getReturnAddresses()) {
//			int index = 0;
//			Iterator<ContextState> contextStates = results.getContextStates(seq);
//			while (contextStates.hasNext()) {
//				dumpReturnState(seq, ++index, contextStates.next(), regList);
//			}
//		}
//		
		List<Register> registers = currentProgram.getLanguage().getRegisters();
		try {
			Register reg = askChoice("Results Query", "Select Register:", registers, null);
			while (reg != null) {
				boolean first = true;
				boolean preserved = true;
				Varnode v = new Varnode(reg.getAddress(), reg.getMinimumByteSize());
				Set<Varnode> returnValues = results.getReturnValues(v);
				for (Varnode val : returnValues) {
					if (!v.equals(val)) {
						preserved = false;
						if (first) {
							first = false;
							System.out.println(reg.getName() + " values: ");
						}
						System.out.println("   " + val.toString(currentProgram.getLanguage()));
					}
				}
				if (preserved) {
					System.out.println(reg.getName() + " value is preserved.");
				}

				reg = askChoice("Results Query", "Select Register:", registers, null);
			}
		}
		catch (CancelledException e) {
		}
	}

	private void dumpStackState(SequenceNumber seq, int index, ContextState state) {
		Language lang = currentProgram.getLanguage();
		System.out.println("Return Stack state #" + index + " at " + seq);
		for (VarnodeOperation op : computedStackAccess) {
// TODO: where do I get the stack storage space ??
			Varnode value = state.get(stackStorageSpaceId, op, op.getSize());
			String valueStr = value != null ? value.toString(lang) : "<unknown>";
			System.out.println(
				"Stack[ " + op.toString(lang) + " ]:" + op.getSize() + " = " + valueStr);
		}
		for (Address addr : stackElementSizes.keySet()) {
			Varnode v = new Varnode(addr, stackElementSizes.get(addr));
			Varnode value = state.get(v);
			String valueStr = value != null ? value.toString(lang) : "<unknown>";
			System.out.println(addr + ":" + v.getSize() + " = " + valueStr);
		}
	}

//	private void dumpReturnState(SequenceNumber seq, int index, ContextState state, List<Register> regList) {
//		System.out.println("Return state #" + index + " at " + seq);
//		for (Register reg : regList) {
//			Varnode v = new Varnode(reg.getAddress(), reg.getMinimumByteSize());
//			Varnode value = state.get(v);
//		}
//	}

	private List<Register> sort(List<Register> list) {
		Collections.sort(list);
		return list;
	}

}
