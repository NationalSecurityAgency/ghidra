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
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;

public class TestTargetStackFrameIsRegisterBank extends
		AbstractTestTargetRegisterBank<TestTargetStackFrameIsRegisterBank, TestTargetStack>
		implements TestTargetStackFrame<TestTargetStackFrameIsRegisterBank> {

	protected Address pc;

	public TestTargetStackFrameIsRegisterBank(TestTargetStack parent, int level) {
		super(parent, PathUtils.makeKey(PathUtils.makeIndex(level)), "Frame",
			parent.getImplParent().getImplParent().getImplParent().regs);
	}

	@Override
	public void setFromFrame(TestTargetStackFrameIsRegisterBank that) {
		this.pc = that.pc;
		changeAttributes(List.of(), Map.of(
			PC_ATTRIBUTE_NAME, this.pc //
		), "Copied frame");
		this.setFromBank(that);
	}

	@Override
	public TestTargetThread getThread() {
		return parent.getImplParent();
	}

	public void setPC(Address address) {
		changeAttributes(List.of(), Map.of(
			PC_ATTRIBUTE_NAME, address //
		), "PC Updated");
	}

	@Override
	public CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values) {
		return writeRegs(values, this::setPC);
	}
}
