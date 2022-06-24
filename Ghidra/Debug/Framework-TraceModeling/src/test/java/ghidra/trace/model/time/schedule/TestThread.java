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
package ghidra.trace.model.time.schedule;

import java.util.List;

import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.ThreadPcodeExecutorState;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;

class TestThread implements PcodeThread<Void> {
	protected final String name;
	protected final TestMachine machine;

	public TestThread(String name, TestMachine machine) {
		this.name = name;
		this.machine = machine;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public TestMachine getMachine() {
		return machine;
	}

	@Override
	public PcodeExecutor<Void> getExecutor() {
		return new PcodeExecutor<>(TraceScheduleTest.TOY_BE_64_LANG, machine.getArithmetic(), getState()) {
			public PcodeFrame execute(PcodeProgram program, PcodeUseropLibrary<Void> library) {
				machine.record.add("x:" + name);
				// TODO: Verify the actual effect
				return null; //super.execute(program, library);
			}
		};
	}

	@Override
	public void stepInstruction() {
		machine.record.add("ti:" + name);
	}

	@Override
	public void skipInstruction() {
		machine.record.add("si:" + name);
	}

	@Override
	public void stepPcodeOp() {
		machine.record.add("tp:" + name);
	}

	@Override
	public void skipPcodeOp() {
		machine.record.add("sp:" + name);
	}

	@Override
	public void setCounter(Address counter) {
	}

	@Override
	public Address getCounter() {
		return null;
	}

	@Override
	public void overrideCounter(Address counter) {
	}

	@Override
	public void assignContext(RegisterValue context) {
	}

	@Override
	public RegisterValue getContext() {
		return null;
	}

	@Override
	public void overrideContext(RegisterValue context) {
	}

	@Override
	public void overrideContextWithDefault() {
	}

	@Override
	public void reInitialize() {
	}

	@Override
	public PcodeFrame getFrame() {
		return null;
	}

	@Override
	public Instruction getInstruction() {
		return null;
	}

	@Override
	public void executeInstruction() {
	}

	@Override
	public void finishInstruction() {
	}

	@Override
	public void dropInstruction() {
	}

	@Override
	public void run() {
	}

	@Override
	public void setSuspended(boolean suspended) {
	}

	@Override
	public PcodeUseropLibrary<Void> getUseropLibrary() {
		return null;
	}

	@Override
	public ThreadPcodeExecutorState<Void> getState() {
		return null;
	}

	@Override
	public void inject(Address address, List<String> sleigh) {
	}

	@Override
	public void clearInject(Address address) {
	}

	@Override
	public void clearAllInjects() {
	}
}
