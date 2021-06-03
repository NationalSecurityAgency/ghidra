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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;

import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.test.AbstractDebuggerModelAttacherTest;
import ghidra.dbg.util.PathUtils;

public abstract class AbstractModelForDbgengRootAttacherTest
		extends AbstractDebuggerModelAttacherTest {

	@Override
	public List<String> getExpectedAttachableContainerPath() {
		return List.of("Available");
	}

	@Override
	public List<String> getExpectedAttacherPath() {
		return PathUtils.parse("");
	}

	@Override
	public DebuggerTestSpecimen getAttachSpecimen() {
		return WindowsSpecimen.NOTEPAD;
	}

	@Override
	public TargetParameterMap getExpectedAttachParameters() {
		return null; // TODO
	}

	@Override
	public void assertEnvironment(TargetEnvironment environment) {
		assertEquals("x86_64", environment.getArchitecture());
		assertEquals("Windows", environment.getOperatingSystem());
		assertEquals("little", environment.getEndian());
		assertTrue(environment.getDebugger().toLowerCase().contains("dbgeng"));
	}
}
