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

import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.test.AbstractDebuggerModelInterpreterTest;
import ghidra.dbg.util.PathUtils;

public abstract class AbstractModelForDbgengInterpreterTest
		extends AbstractDebuggerModelInterpreterTest {

	@Override
	protected List<String> seedPath() {
		return PathUtils.parse("Sessions[0]");
	}

	@Override
	public List<String> getExpectedInterpreterPath() {
		return PathUtils.parse("Sessions[0]");
	}

	@Override
	protected String getEchoCommand(String msg) {
		return ".echo " + msg;
	}

	@Override
	protected String getQuitCommand() {
		return "q";
	}

	@Override
	protected String getAttachCommand() {
		return ".attach " + Long.toHexString(dummy.pid);
	}

	@Override
	protected String getDetachCommand(TargetProcess process) {
		return ".detach";
	}

	@Override
	protected String getKillCommand(TargetProcess process) {
		return ".kill";
	}

	@Override
	public DebuggerTestSpecimen getAttachSpecimen() {
		return WindowsSpecimen.NOTEPAD;
	}

	@Override
	public DebuggerTestSpecimen getLaunchSpecimen() {
		return WindowsSpecimen.PRINT;
	}

	/*
	@Override
	@Ignore
	@Test(expected = DebuggerModelTerminatingException.class)
	public void testExecuteQuit() throws Throwable {
		// Different behavior for dbg clients vice gdb
	}
	*/

}
