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

import ghidra.program.model.address.AddressSpace;

public class TestTargetProcessContainer
		extends DefaultTestTargetObject<TestTargetProcess, TestTargetSession> {
	public TestTargetProcessContainer(TestTargetSession parent) {
		super(parent, "Processes", "Processes");
	}

	public TestTargetProcess addProcess(int pid, AddressSpace space) {
		TestTargetProcess proc = new TestTargetProcess(this, pid, space);
		changeElements(List.of(), List.of(proc), Map.of(), "Test Process Added");
		return proc;
	}

	public void removeProcess(TestTargetProcess process) {
		changeElements(List.of(process.getIndex()), List.of(),
			"Test Process Removed: " + process.getPid());
	}
}
