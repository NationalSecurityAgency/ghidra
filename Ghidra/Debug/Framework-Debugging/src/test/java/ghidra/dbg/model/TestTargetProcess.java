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

import ghidra.dbg.target.TargetAggregate;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.AddressRange;

public class TestTargetProcess extends
		DefaultTestTargetObject<TestTargetProcessContainer, TestTargetObject>
		implements TargetProcess, TargetAggregate {
	public final TestTargetBreakpointContainer breaks;
	public final TestTargetMemory memory;
	public final TestTargetModuleContainer modules;
	public final TestTargetRegisterContainer regs;
	public final TestTargetThreadContainer threads;

	public TestTargetProcess(DefaultTestTargetObject<?, ?> parent, int pid) {
		super(parent, PathUtils.makeKey(PathUtils.makeIndex(pid)), "Process");
		breaks = new TestTargetBreakpointContainer(this);
		memory = new TestTargetMemory(this);
		modules = new TestTargetModuleContainer(this);
		regs = new TestTargetRegisterContainer(this);
		threads = new TestTargetThreadContainer(this);

		changeAttributes(List.of(), List.of(
			breaks,
			memory,
			modules,
			regs,
			threads),
			Map.of(), "Initialized");
	}

	public TestTargetModule addModule(String name, AddressRange range) {
		return modules.addModule(name, range);
	}

	public TestTargetMemoryRegion addRegion(String name, AddressRange range, String flags) {
		return memory.addRegion(name, range, flags);
	}

	public TestTargetThread addThread(int tid) {
		return threads.addThread(tid);
	}

	public void removeThreads(TestTargetThread... threads) {
		this.threads.removeThreads(threads);
	}
}
