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

import java.util.ArrayList;
import java.util.List;

import ghidra.dbg.target.TargetStack;
import ghidra.program.model.address.Address;

public class TestTargetStack extends DefaultTestTargetObject<TestTargetStackFrame, TestTargetThread>
		implements TargetStack {

	public TestTargetStack(TestTargetThread parent) {
		super(parent, "Stack", "Stack");
	}

	protected <T extends TestTargetStackFrame> T pushFrame(T frame) {
		List<TestTargetStackFrame> list = new ArrayList<>((elements.values()));
		list.add(frame);
		for (int i = list.size() - 1; i > 1; i--) {
			list.get(i).setFromFrame(list.get(i - 1));
		}
		changeElements(List.of(), List.of(frame), "Pushed test frame");
		return frame;
	}

	/**
	 * Push a new frame onto the stack where the register bank is a child attribute
	 * 
	 * @return the "new" highest-indexed frame, into which old data was pushed
	 */
	public TestTargetStackFrameHasRegisterBank pushFrameHasBank(Address pc) {
		return pushFrame(new TestTargetStackFrameHasRegisterBank(this, elements.size(), pc));
	}

	/**
	 * Push a new frame onto the stack which is also the registers bank
	 * 
	 * @return the "new" highest-indexed frame, into which old data was pushed
	 */
	public TestTargetStackFrameIsRegisterBank pushFrameIsBank(Address pc) {
		return pushFrame(new TestTargetStackFrameIsRegisterBank(this, elements.size(), pc));
	}
}
