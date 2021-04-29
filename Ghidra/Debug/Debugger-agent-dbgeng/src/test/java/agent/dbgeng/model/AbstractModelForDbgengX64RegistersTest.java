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
package agent.dbgeng.model;

import java.util.List;
import java.util.Map;

import ghidra.dbg.test.*;
import ghidra.dbg.util.PathUtils;

public abstract class AbstractModelForDbgengX64RegistersTest
		extends AbstractDebuggerModelRegistersTest
		implements ProvidesTargetViaLaunchSpecimen {
	public final Map<String, byte[]> REG_VALS = Map.ofEntries(
		Map.entry("rax", arr("0123456789abcdef")),
		Map.entry("ymm0", arr(
			"0123456789abcdef" + "fedcba9876543210" // TODO: Why 16 bytes instead of 32? 
		/*+ "0011223344556677" + "8899aabbccddeeff"*/)));

	@Override
	public AbstractDebuggerModelTest getTest() {
		return this;
	}

	@Override
	public List<String> getExpectedRegisterBankPath(List<String> threadPath) {
		return PathUtils.extend(threadPath, PathUtils.parse("Registers"));
	}

	@Override
	public Map<String, byte[]> getRegisterWrites() {
		return REG_VALS;
	}

	@Override
	public DebuggerTestSpecimen getLaunchSpecimen() {
		return WindowsSpecimen.PRINT;
	}
}
