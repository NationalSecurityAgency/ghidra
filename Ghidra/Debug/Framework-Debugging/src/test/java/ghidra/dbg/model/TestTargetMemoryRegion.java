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

import ghidra.dbg.target.TargetMemoryRegion;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.AddressRange;

public class TestTargetMemoryRegion
		extends DefaultTestTargetObject<TestTargetObject, TestTargetMemory>
		implements TargetMemoryRegion {

	public TestTargetMemoryRegion(TestTargetMemory parent, String name, AddressRange range,
			String flags) {
		super(parent, PathUtils.makeKey(name), "MemoryRegion");

		changeAttributes(List.of(), Map.of(
			MEMORY_ATTRIBUTE_NAME, parent,
			RANGE_ATTRIBUTE_NAME, range,
			READABLE_ATTRIBUTE_NAME, flags.contains("r"),
			WRITABLE_ATTRIBUTE_NAME, flags.contains("w"),
			EXECUTABLE_ATTRIBUTE_NAME, flags.contains("x") //
		), "Initialized");
	}
}
