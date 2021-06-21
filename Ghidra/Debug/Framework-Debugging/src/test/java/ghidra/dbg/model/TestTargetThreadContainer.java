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
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.dbg.target.TargetObject;

public class TestTargetThreadContainer
		extends DefaultTestTargetObject<TestTargetThread, TestTargetProcess> {
	public TestTargetThreadContainer(TestTargetProcess parent) {
		super(parent, "Threads", "Threads");
	}

	public TestTargetThread addThread(int tid) {
		TestTargetThread thread = new TestTargetThread(this, tid);
		changeElements(List.of(), List.of(thread), Map.of(), "Test Thread Added");
		return thread;
	}

	public void removeThreads(TestTargetThread[] threads) {
		List<String> indices =
			Stream.of(threads).map(TargetObject::getIndex).collect(Collectors.toList());
		changeElements(indices, List.of(), Map.of(), "Test Threads Removed");
	}
}
