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
package ghidra.app.plugin.core.select.flow;

import org.junit.After;
import org.junit.Before;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.block.FollowFlow;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.DataConverter;
import ghidra.util.task.TaskMonitorAdapter;

public abstract class AbstractFollowFlowTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	PluginTool tool;
	ProgramDB program;
	DataConverter dataConverter;
	ProgramBuilder builder;

	AddressFactory addressFactory;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();

		builder = new FollowFlowProgramBuilder();
		program = builder.getProgram();
		addressFactory = program.getAddressFactory();

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
	}

	@After
	public void tearDown() throws Exception {

		env.dispose();
	}

	AddressSetView getFlowsFrom(int startAddressOffset, FlowType[] excludedFlows) {
		return getFlowsFrom(addr(startAddressOffset), excludedFlows);
	}

	AddressSetView getFlowsFrom(Address startAddress, FlowType[] excludedFlows) {
		return getFlowsFrom(new AddressSet(startAddress), excludedFlows);
	}

	AddressSetView getFlowsFrom(AddressSet startSet, FlowType[] excludedFlows) {
		FollowFlow followFlow = new FollowFlow(program, startSet, excludedFlows);
		return followFlow.getFlowAddressSet(TaskMonitorAdapter.DUMMY_MONITOR);
	}

	AddressSetView getFlowsTo(int startAddressOffset, FlowType[] excludedFlows) {
		return getFlowsTo(addr(startAddressOffset), excludedFlows);
	}

	AddressSetView getFlowsTo(Address startAddress, FlowType[] excludedFlows) {
		return getFlowsTo(new AddressSet(startAddress), excludedFlows);
	}

	AddressSetView getFlowsTo(AddressSet startSet, FlowType[] excludedFlows) {
		FollowFlow followFlow = new FollowFlow(program, startSet, excludedFlows);
		return followFlow.getFlowToAddressSet(TaskMonitorAdapter.DUMMY_MONITOR);
	}

	FlowType[] followAllFlows() {
		FlowType[] flowsNotToFollow = new FlowType[] {};
		return flowsNotToFollow;
	}

	FlowType[] followOnlyComputedCalls() {
		FlowType[] flowsNotToFollow =
			new FlowType[] { RefType.CONDITIONAL_CALL, RefType.UNCONDITIONAL_CALL,
				RefType.COMPUTED_JUMP, RefType.CONDITIONAL_JUMP, RefType.UNCONDITIONAL_JUMP,
				RefType.INDIRECTION };
		return flowsNotToFollow;
	}

	FlowType[] followOnlyConditionalCalls() {
		FlowType[] flowsNotToFollow =
			new FlowType[] { RefType.COMPUTED_CALL, RefType.UNCONDITIONAL_CALL,
				RefType.COMPUTED_JUMP, RefType.CONDITIONAL_JUMP, RefType.UNCONDITIONAL_JUMP,
				RefType.INDIRECTION };
		return flowsNotToFollow;
	}

	FlowType[] followOnlyUnconditionalCalls() {
		FlowType[] flowsNotToFollow =
			new FlowType[] { RefType.COMPUTED_CALL, RefType.CONDITIONAL_CALL,
				RefType.COMPUTED_JUMP, RefType.CONDITIONAL_JUMP, RefType.UNCONDITIONAL_JUMP,
				RefType.INDIRECTION };
		return flowsNotToFollow;
	}

	FlowType[] followOnlyComputedJumps() {
		FlowType[] flowsNotToFollow =
			new FlowType[] { RefType.COMPUTED_CALL, RefType.CONDITIONAL_CALL,
				RefType.UNCONDITIONAL_CALL, RefType.CONDITIONAL_JUMP, RefType.UNCONDITIONAL_JUMP,
				RefType.INDIRECTION };
		return flowsNotToFollow;
	}

	FlowType[] followOnlyConditionalJumps() {
		FlowType[] flowsNotToFollow =
			new FlowType[] { RefType.COMPUTED_CALL, RefType.CONDITIONAL_CALL,
				RefType.UNCONDITIONAL_CALL, RefType.COMPUTED_JUMP, RefType.UNCONDITIONAL_JUMP,
				RefType.INDIRECTION };
		return flowsNotToFollow;
	}

	FlowType[] followOnlyUnconditionalJumps() {
		FlowType[] flowsNotToFollow =
			new FlowType[] { RefType.COMPUTED_CALL, RefType.CONDITIONAL_CALL,
				RefType.UNCONDITIONAL_CALL, RefType.COMPUTED_JUMP, RefType.CONDITIONAL_JUMP,
				RefType.INDIRECTION };
		return flowsNotToFollow;
	}

	FlowType[] followOnlyPointers() {
		FlowType[] flowsNotToFollow =
			new FlowType[] { RefType.COMPUTED_CALL, RefType.CONDITIONAL_CALL,
				RefType.UNCONDITIONAL_CALL, RefType.COMPUTED_JUMP, RefType.CONDITIONAL_JUMP,
				RefType.UNCONDITIONAL_JUMP };
		return flowsNotToFollow;
	}

	FlowType[] followNoFlows() {
		FlowType[] flowsNotToFollow =
			new FlowType[] { RefType.COMPUTED_CALL, RefType.CONDITIONAL_CALL,
				RefType.UNCONDITIONAL_CALL, RefType.COMPUTED_JUMP, RefType.CONDITIONAL_JUMP,
				RefType.UNCONDITIONAL_JUMP, RefType.INDIRECTION };
		return flowsNotToFollow;
	}

	FlowType[] followConditionalAndUnconditionalJumps() {
		FlowType[] flowsNotToFollow =
			new FlowType[] { RefType.COMPUTED_CALL, RefType.CONDITIONAL_CALL,
				RefType.UNCONDITIONAL_CALL, RefType.COMPUTED_JUMP, RefType.INDIRECTION };
		return flowsNotToFollow;
	}

	FlowType[] followAllJumps() {
		FlowType[] flowsNotToFollow =
			new FlowType[] { RefType.COMPUTED_CALL, RefType.CONDITIONAL_CALL,
				RefType.UNCONDITIONAL_CALL, RefType.INDIRECTION };
		return flowsNotToFollow;
	}

	FlowType[] followAllCalls() {
		FlowType[] flowsNotToFollow =
			new FlowType[] { RefType.COMPUTED_JUMP, RefType.CONDITIONAL_JUMP,
				RefType.UNCONDITIONAL_JUMP, RefType.INDIRECTION };
		return flowsNotToFollow;
	}

	Address addr(int addr) {
		return builder.addr("0x" + Integer.toHexString(addr));
	}

	class MySelection extends ProgramSelection {

		MySelection(ProgramSelection selection) {
			super(selection);
		}

		MySelection(AddressSetView addressSet) {
			super(addressSet);
		}

		@Override
		public String toString() {
			StringBuffer buf = new StringBuffer();
			AddressRangeIterator ranges = getAddressRanges();
			for (AddressRange addressRange : ranges) {
				buf.append("\n[" + addressRange.getMinAddress() + " - " +
					addressRange.getMaxAddress() + "]");
			}
			return buf.toString();
		}
	}
}
