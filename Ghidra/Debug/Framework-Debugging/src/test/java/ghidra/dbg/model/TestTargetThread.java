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
package ghidra.dbg.model;

import java.util.List;
import java.util.Map;

import ghidra.dbg.target.TargetExecutionStateful;
import ghidra.dbg.target.TargetThread;
import ghidra.dbg.util.CollectionUtils.Delta;
import ghidra.dbg.util.PathUtils;

public class TestTargetThread
		extends DefaultTestTargetObject<TestTargetObject, TestTargetThreadContainer>
		implements TargetThread, TargetExecutionStateful {
	public TestTargetThread(TestTargetThreadContainer parent, int tid) {
		super(parent, PathUtils.makeKey(PathUtils.makeIndex(tid)), "Thread");
		changeAttributes(List.of(), List.of(), Map.of(
			STATE_ATTRIBUTE_NAME, TargetExecutionState.STOPPED //
		), "Initialized");
	}

	/**
	 * Treat this thread as not having frame information, and just expose the registers
	 * 
	 * @return the created register bank
	 */
	public TestTargetRegisterBankInThread addRegisterBank() {
		TestTargetRegisterBankInThread regs = new TestTargetRegisterBankInThread(this);
		changeAttributes(List.of(), List.of(
			regs),
			Map.of(), "Add Test Register Bank");
		return regs;
	}

	public TestTargetStack addStack() {
		TestTargetStack stack = new TestTargetStack(this);
		changeAttributes(List.of(), List.of(
			stack),
			Map.of(), "Add Test Stack");
		return stack;
	}

	public void setState(TargetExecutionState state) {
		Delta<?, ?> delta = changeAttributes(List.of(), List.of(), Map.of(
			STATE_ATTRIBUTE_NAME, state //
		), "Changed state");
	}
}
