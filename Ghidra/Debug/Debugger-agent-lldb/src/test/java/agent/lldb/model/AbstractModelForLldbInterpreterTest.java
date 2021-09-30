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
package agent.lldb.model;

import java.util.List;

import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.test.*;
import ghidra.dbg.util.PathUtils;

public abstract class AbstractModelForLldbInterpreterTest
		extends AbstractDebuggerModelInterpreterTest
		implements ProvidesTargetViaLaunchSpecimen {

	@Override
	public AbstractDebuggerModelTest getTest() {
		return this;
	}

	@Override
	protected void ensureInterpreterAvailable() throws Throwable {
		obtainTarget();
	}

	@Override
	protected List<String> seedPath() {
		return List.of();
		//return PathUtils.parse("Sessions[1]");
	}

	@Override
	public List<String> getExpectedInterpreterPath() {
		return PathUtils.parse("Sessions[1]");
	}

	@Override
	protected String getEchoCommand(String msg) {
		return "script print(\'" + msg + "\')";
	}

	@Override
	protected String getQuitCommand() {
		return "quit";
	}

	@Override
	protected String getAttachCommand() {
		return "process attach " + Long.toHexString(dummy.pid);
	}

	@Override
	protected String getDetachCommand(TargetProcess process) {
		return "process detach";
	}

	@Override
	protected String getKillCommand(TargetProcess process) {
		return "kill";
	}

	@Override
	public DebuggerTestSpecimen getAttachSpecimen() {
		return MacOSSpecimen.SPIN;
	}

	@Override
	public DebuggerTestSpecimen getLaunchSpecimen() {
		return MacOSSpecimen.PRINT;
	}

}
