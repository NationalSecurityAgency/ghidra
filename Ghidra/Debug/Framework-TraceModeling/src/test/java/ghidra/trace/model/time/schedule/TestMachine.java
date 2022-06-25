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

import java.util.ArrayList;
import java.util.List;

import ghidra.pcode.emu.AbstractPcodeMachine;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeUseropLibrary;

class TestMachine extends AbstractPcodeMachine<Void> {
	protected final List<String> record = new ArrayList<>();

	public TestMachine() {
		super(TraceScheduleTest.TOY_BE_64_LANG, null);
	}

	@Override
	protected PcodeThread<Void> createThread(String name) {
		return new TestThread(name, this);
	}

	@Override
	protected PcodeExecutorState<Void> createSharedState() {
		return null;
	}

	@Override
	protected PcodeExecutorState<Void> createLocalState(PcodeThread<Void> thread) {
		return null;
	}

	@Override
	protected PcodeUseropLibrary<Void> createUseropLibrary() {
		return PcodeUseropLibrary.nil();
	}
}
